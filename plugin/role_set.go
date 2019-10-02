package gcpsecrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"regexp"
	"time"
)

const (
	serviceAccountMaxLen          = 30
	serviceAccountDisplayNameTmpl = "Service account for Vault secrets backend role set %s"
)

type RoleSet struct {
	Name       string
	SecretType string

	RawBindings string
	Bindings    ResourceBindings

	AccountId *gcputil.ServiceAccountId
	TokenGen  *TokenGenerator
}

func (rs *RoleSet) validate() error {
	var err *multierror.Error
	if rs.Name == "" {
		err = multierror.Append(err, errors.New("role set name is empty"))
	}

	if rs.SecretType == "" {
		err = multierror.Append(err, errors.New("role set secret type is empty"))
	}

	if rs.AccountId == nil {
		err = multierror.Append(err, fmt.Errorf("role set should have account associated"))
	}

	if rs.Bindings == nil {
		err = multierror.Append(err, fmt.Errorf("role set bindings cannot be nil"))
	}

	switch rs.SecretType {
	case SecretTypeAccessToken:
		if rs.TokenGen == nil {
			err = multierror.Append(err, fmt.Errorf("access token role set should have initialized token generator"))
		} else if len(rs.TokenGen.Scopes) == 0 {
			err = multierror.Append(err, fmt.Errorf("access token role set should have defined scopes"))
		}
	case SecretTypeKey:
		break
	default:
		err = multierror.Append(err, fmt.Errorf("unknown secret type: %s", rs.SecretType))
	}
	return err.ErrorOrNil()
}

func (rs *RoleSet) save(ctx context.Context, s logical.Storage) error {
	if err := rs.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesetStoragePrefix, rs.Name), rs)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (rs *RoleSet) bindingHash() string {
	return getStringHash(rs.RawBindings)
}

func (rs *RoleSet) getServiceAccount(iamAdmin *iam.Service) (*iam.ServiceAccount, error) {
	if rs.AccountId == nil {
		return nil, fmt.Errorf("role set '%s' is invalid, has no associated service account", rs.Name)
	}

	account, err := iamAdmin.Projects.ServiceAccounts.Get(rs.AccountId.ResourceName()).Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account: %v. If account was deleted, role set must be updated (write to roleset/%s/rotate) before generating new secrets", err, rs.Name)
	} else if account == nil {
		return nil, fmt.Errorf("roleset service account was removed - role set must be updated (path roleset/%s/rotate) before generating new secrets", rs.Name)
	}

	return account, nil
}

type ResourceBindings map[string]util.StringSet

func (rb ResourceBindings) asOutput() map[string][]string {
	out := make(map[string][]string)
	for k, v := range rb {
		out[k] = v.ToSlice()
	}
	return out
}

type TokenGenerator struct {
	KeyName    string
	B64KeyJSON string

	Scopes []string
}

func (b *backend) saveRoleSetWithNewAccount(
	ctx context.Context, s logical.Storage, rs *RoleSet,
	project, newAccountName string, newBinds ResourceBindings, scopes []string) (warning []string, err error) {
	if rs == nil {
		return nil, fmt.Errorf("expected non-nil roleset - GCP plugin error")
	}

	b.Logger().Debug("creating new account for roleset", "roleset", rs.Name)

	oldAccount := rs.AccountId
	oldBindings := rs.Bindings
	oldTokenKey := rs.TokenGen

	if oldAccount != nil {
		// Add WALs to make sure we clean up old account if needed
		err := b.addWalsForAllAccountResources(ctx, s, rs.Name, oldAccount, oldBindings, oldTokenKey)
		if err != nil {
			return nil, errwrap.Wrapf("failed to create WALs for cleaning up old account: {{err}}", err)
		}
	}

	// Create new account
	accountId, err := b.createNewAccountWithWal(ctx, s, rs.Name, project, newAccountName)
	if err != nil {
		return nil, err
	}
	rs.AccountId = accountId
	b.Logger().Debug("set new accountId for roleset", "roleset", rs.Name, "accountId", accountId)

	// Add resource bindings
	err = b.addResourceBindingsWithWals(ctx, s, rs.Name, accountId, newBinds)
	if err != nil {
		return nil, err
	}
	rs.Bindings = newBinds
	b.Logger().Debug("set bindings for roleset", "roleset", rs.Name, "bindings", newBinds)

	// Create tokenGenerator if needed.
	if rs.SecretType == SecretTypeAccessToken {
		tokenGen, err := b.createAccountTokenGeneratorWithWal(ctx, s, rs.Name, accountId, scopes)
		if err != nil {
			return nil, err
		}
		rs.TokenGen = tokenGen
		b.Logger().Debug("set new tokenGen for roleset", "roleset", rs.Name, "key", tokenGen.KeyName)
	}

	if err := rs.save(ctx, s); err != nil {
		return nil, errwrap.Wrapf("unable to save roleset to storage: {{err}}", err)
	}

	if oldAccount != nil {
		// Try deleting old resources (WALs exist so we can ignore failures)
		return b.tryCleanAccountResources(ctx, s, rs.Name, oldAccount, oldBindings, oldTokenKey), nil
	}
	return nil, nil
}

func (b *backend) saveRolesetWithNewTokenGenerator(ctx context.Context, s logical.Storage, rs *RoleSet, scopes []string) (warnings []string, err error) {
	if rs == nil {
		return nil, fmt.Errorf("expected non-nil roleset - GCP plugin error")
	}

	if rs.SecretType != SecretTypeAccessToken {
		return nil, fmt.Errorf("cannot rotate token gen - non-access-token role set %q has secret_type %q", rs.Name, rs.SecretType)
	}
	b.Logger().Debug("creating new token generator key for roleset", "roleset", rs.Name)

	oldTokenGen := rs.TokenGen
	if oldTokenGen != nil {
		scopes = oldTokenGen.Scopes
		if _, err := framework.PutWAL(ctx, s, walTypeAccountKey, &walAccountKey{
			RoleSet:            rs.Name,
			KeyName:            oldTokenGen.KeyName,
			ServiceAccountName: rs.AccountId.ResourceName(),
		}); err != nil {
			return nil, errwrap.Wrapf("unable to create WAL for deleting old key: {{err}}", err)
		}
	}

	tokenGen, err := b.createAccountTokenGeneratorWithWal(ctx, s, rs.Name, rs.AccountId, scopes)
	if err != nil {
		return nil, err
	}
	rs.TokenGen = tokenGen

	if err := rs.save(ctx, s); err != nil {
		return nil, errwrap.Wrapf("unable to save roleset to storage: {{err}}", err)
	}

	return b.tryCleanAccountTokenGen(ctx, s, rs.Name, oldTokenGen), nil
}

// Attempt to delete account, bindings, and tokenGen. This method assumes that WAL
// entries have been added for each operation.
func (b *backend) tryCleanAccountResources(ctx context.Context, s logical.Storage, rsName string, accountId *gcputil.ServiceAccountId, bindings ResourceBindings, tokenGen *TokenGenerator) []string {
	if accountId == nil {
		b.Logger().Debug("account cleanup called for nil account ID, skipping")
		return nil
	}

	httpC, err := b.HTTPClient(s)
	if err != nil {
		return []string{fmt.Sprintf("unable to clean up unused resources, will try again later - could not create http client: %v", err)}
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return []string{fmt.Sprintf("unable to clean up unused resources, will try again later - could not create iam admin client: %v", err)}
	}

	iamHandle := iamutil.GetIamHandle(httpC, useragent.String())
	warnings := make([]string, 0)
	if tokenGen != nil {
		if err := b.deleteTokenGenKey(ctx, iamAdmin, tokenGen); err != nil {
			w := fmt.Sprintf("unable to clean up unused key %q, will try again later - %v", tokenGen.KeyName, err)
			warnings = append(warnings, w)
		}
	}

	if err := b.deleteServiceAccount(ctx, iamAdmin, accountId); err != nil {
		w := fmt.Sprintf("unable to clean up unused account %q, will try again later - %v", accountId.ResourceName(), err)
		warnings = append(warnings, w)
	}

	if merr := b.removeBindings(ctx, iamHandle, accountId.EmailOrId, bindings); merr != nil {
		for _, err := range merr.Errors {
			w := fmt.Sprintf("unable to clean up unused bindings for %q, will try again later - %v", accountId.EmailOrId, err)
			warnings = append(warnings, w)
		}
	}

	return warnings
}

// Attempt to delete only tokenGen. This method assumes that WAL
// entries have been added for each operation.
func (b *backend) tryCleanAccountTokenGen(ctx context.Context, s logical.Storage, rsName string, tokenGen *TokenGenerator) []string {
	if tokenGen == nil {
		b.Logger().Debug("token gen cleanup called for nil account ID, skipping")
		return nil
	}

	httpC, err := b.HTTPClient(s)
	if err != nil {
		return []string{fmt.Sprintf("unable to clean up unused resources, will try again later - could not create http client: %v", err)}
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return []string{fmt.Sprintf("unable to clean up unused resources, will try again later - could not create iam admin client: %v", err)}
	}

	warnings := make([]string, 0)
	if err := b.deleteTokenGenKey(ctx, iamAdmin, tokenGen); err != nil {
		w := fmt.Sprintf("unable to clean up unused key %q, will try again later - %v", tokenGen.KeyName, err)
		warnings = append(warnings, w)
	}
	return warnings
}

// Add cleanup callbacks to WALs. They will delete account, bindings, and tokenGen
// (account key) ONLY if they are not used by the roleset saved under the name.
func (b *backend) addWalsForAllAccountResources(ctx context.Context, s logical.Storage, rsName string, accountId *gcputil.ServiceAccountId, bindings ResourceBindings, tokenGen *TokenGenerator) error {
	if accountId == nil {
		b.Logger().Debug("No WALs to add prior to deletion, given nil service account ID")
		return nil
	}

	b.Logger().Debug("add WAL for account deletion", "walType", walTypeAccount, "account", accountId)
	_, err := framework.PutWAL(ctx, s, walTypeAccount, &walAccount{
		RoleSet: rsName,
		Id:      *accountId,
	})
	if err != nil {
		return errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
	}

	for resName, roles := range bindings {
		b.Logger().Debug("add WAL for removing binding", "walType", walTypeIamPolicy, "account", accountId, "resource", resName, "roles", roles)
		_, err := framework.PutWAL(ctx, s, walTypeIamPolicy, &walIamPolicy{
			RoleSet:   rsName,
			AccountId: *accountId,
			Resource:  resName,
			Roles:     roles.ToSlice(),
		})
		if err != nil {
			return errwrap.Wrapf("unable to create WAL entry to clean up service account bindings: {{err}}", err)
		}
	}

	if tokenGen != nil {
		b.Logger().Debug("add WAL for token gen deletion", "walType", walTypeAccount, "key", tokenGen.KeyName)
		_, err := framework.PutWAL(ctx, s, walTypeAccountKey, &walAccountKey{
			RoleSet:            rsName,
			ServiceAccountName: accountId.ResourceName(),
			KeyName:            tokenGen.KeyName,
		})
		if err != nil {
			return errwrap.Wrapf("unable to create WAL entry to clean up service account key: {{err}}", err)
		}
	}
	return nil
}

func (b *backend) createNewAccountWithWal(ctx context.Context, s logical.Storage, rolesetName, project, newAccountName string) (*gcputil.ServiceAccountId, error) {
	b.Logger().Debug("creating new account", "project", project, "newAccountName", newAccountName)

	accountId := &gcputil.ServiceAccountId{
		Project:   project,
		EmailOrId: fmt.Sprintf("%s@%s.iam.gserviceaccount.com", newAccountName, project),
	}
	b.Logger().Debug("add WAL for account deletion", "walType", walTypeAccount, "account", accountId)
	_, err := framework.PutWAL(ctx, s, walTypeAccount, &walAccount{
		RoleSet: rolesetName,
		Id:      *accountId,
	})
	if err != nil {
		return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
	}

	httpC, err := b.HTTPClient(s)
	if err != nil {
		return nil, errwrap.Wrapf("could not create http client: {{err}}", err)
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return nil, errwrap.Wrapf("could not create IAM admin client: {{err}}", err)
	}

	projectName := fmt.Sprintf("projects/%s", project)
	displayName := fmt.Sprintf(serviceAccountDisplayNameTmpl, rolesetName)
	sa, err := iamAdmin.Projects.ServiceAccounts.Create(
		projectName, &iam.CreateServiceAccountRequest{
			AccountId:      newAccountName,
			ServiceAccount: &iam.ServiceAccount{DisplayName: displayName},
		}).Do()
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to create new service account under project '%s': {{err}}", projectName), err)
	}
	return &gcputil.ServiceAccountId{
		Project:   sa.ProjectId,
		EmailOrId: sa.Email,
	}, nil
}

func (b *backend) createAccountTokenGeneratorWithWal(ctx context.Context, s logical.Storage, rolesetName string,
	account *gcputil.ServiceAccountId, scopes []string) (*TokenGenerator, error) {
	if account == nil {
		return nil, fmt.Errorf("cannot create token gen for nil accountId")
	}
	b.Logger().Debug("creating token generator", "account", account.ResourceName(), "scopes", scopes)

	httpC, err := b.HTTPClient(s)
	if err != nil {
		return nil, errwrap.Wrapf("could not create http client: {{err}}", err)
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return nil, errwrap.Wrapf("could not create IAM admin client: {{err}}", err)
	}

	key, err := iamAdmin.Projects.ServiceAccounts.Keys.Create(
		account.ResourceName(),
		&iam.CreateServiceAccountKeyRequest{
			PrivateKeyType: privateKeyTypeJson,
		}).Do()
	if err != nil {
		return nil, errwrap.Wrapf("unable to create service account key: {{err}}", err)
	}

	// In case the roleset does not have this saved later, we add a WAL.
	b.Logger().Debug("add WAL for cleaning up token gen key", "walType", walTypeAccountKey, "key", key.Name)
	_, err = framework.PutWAL(ctx, s, walTypeAccountKey, &walAccountKey{
		RoleSet:            rolesetName,
		ServiceAccountName: account.ResourceName(),
		KeyName:            key.Name,
	})
	if err != nil {
		b.Logger().Error("unable to create WAL entry to clean up service account key %q in case of error, may need to be done manually", key.Name)
	}

	return &TokenGenerator{
		KeyName:    key.Name,
		B64KeyJSON: key.PrivateKeyData,
		Scopes:     scopes,
	}, nil
}

func (b *backend) addResourceBindingsWithWals(ctx context.Context, s logical.Storage, rolesetName string,
	account *gcputil.ServiceAccountId, bindings ResourceBindings) error {

	b.Logger().Debug("adding resource bindings", "account", account.ResourceName(), "bindings", bindings.asOutput())

	httpC, err := b.HTTPClient(s)
	if err != nil {
		return errwrap.Wrapf("could not create http client: {{err}}", err)
	}
	iamHandle := iamutil.GetIamHandle(httpC, useragent.String())

	enabledIamResources := b.iamResources
	for rName, roles := range bindings {
		resource, err := enabledIamResources.Parse(rName)
		if err != nil {
			return err
		}

		p, err := iamHandle.GetIamPolicy(ctx, resource)
		if err != nil {
			return err
		}

		changed, newP := p.AddBindings(&iamutil.PolicyDelta{
			Roles: roles,
			Email: account.EmailOrId,
		})
		if !changed || newP == nil {
			continue
		}

		if _, err := iamHandle.SetIamPolicy(ctx, resource, newP); err != nil {
			return err
		}
	}
	return nil
}

func randomServiceAccountName(rsName string) (name string) {
	// Sanitize role name
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	rsName = reg.ReplaceAllString(rsName, "-")

	intSuffix := fmt.Sprintf("%d", time.Now().Unix())
	fullName := fmt.Sprintf("vault%s-%s", rsName, intSuffix)
	name = fullName
	if len(fullName) > serviceAccountMaxLen {
		toTrunc := len(fullName) - serviceAccountMaxLen
		name = fmt.Sprintf("vault%s-%s", rsName[:len(rsName)-toTrunc], intSuffix)
	}
	return name
}

func getStringHash(bindingsRaw string) string {
	ssum := sha256.Sum256([]byte(bindingsRaw)[:])
	return base64.StdEncoding.EncodeToString(ssum[:])
}
