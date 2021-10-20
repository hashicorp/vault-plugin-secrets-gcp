package gcpsecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) getImpersonatedAccount(name string, ctx context.Context, s logical.Storage) (*ImpersonatedAccount, error) {
	b.Logger().Debug("getting impersonated account from storage", "impersonated_account_name", name)
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", impersonatedAccountStoragePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	a := &ImpersonatedAccount{}
	if err := entry.DecodeJSON(a); err != nil {
		return nil, err
	}
	return a, nil
}

type ImpersonatedAccount struct {
	Name       string
	SecretType string
	gcputil.ServiceAccountId

	TokenScopes []string
}

func (a *ImpersonatedAccount) validate() error {
	err := &multierror.Error{}
	if a.Name == "" {
		err = multierror.Append(err, errors.New("impersonated account name is empty"))
	}

	if a.SecretType == "" {
		err = multierror.Append(err, errors.New("impersonated account secret type is empty"))
	}

	if a.EmailOrId == "" {
		err = multierror.Append(err, fmt.Errorf("impersonated account must have service account email"))
	}

	switch a.SecretType {
	case SecretTypeAccessToken:
		if len(a.TokenScopes) == 0 {
			err = multierror.Append(err, fmt.Errorf("access token impersonated account should have defined scopes"))
		}
	case SecretTypeKey:
		break
	default:
		err = multierror.Append(err, fmt.Errorf("unknown secret type: %s", a.SecretType))
	}
	return err.ErrorOrNil()
}

func (a *ImpersonatedAccount) save(ctx context.Context, s logical.Storage) error {
	if err := a.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", impersonatedAccountStoragePrefix, a.Name), a)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) tryDeleteImpersonatedAccountResources(ctx context.Context, req *logical.Request, boundResources *gcpAccountResources, walIds []string) []string {
	return b.tryDeleteGcpAccountResources(ctx, req, boundResources, flagMustKeepServiceAccount, walIds)
}

func (b *backend) createImpersonatedAccount(ctx context.Context, req *logical.Request, input *inputParams) (err error) {
	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return err
	}

	gcpAcct, err := b.getServiceAccount(iamAdmin, &gcputil.ServiceAccountId{
		Project:   gcpServiceAccountInferredProject,
		EmailOrId: input.serviceAccountEmail,
	})
	if err != nil {
		if isGoogleAccountNotFoundErr(err) {
			return fmt.Errorf("unable to create impersonated account, service account %q should exist", input.serviceAccountEmail)
		}
		return errwrap.Wrapf(fmt.Sprintf("unable to create impersonated account, could not confirm service account %q exists: {{err}}", input.serviceAccountEmail), err)
	}

	acctId := gcputil.ServiceAccountId{
		Project:   gcpAcct.ProjectId,
		EmailOrId: gcpAcct.Email,
	}

	// Construct gcpAccountResources references. Note bindings/key are yet to be created.
	newResources := &gcpAccountResources{
		accountId: acctId,
	}
	if input.secretType == SecretTypeAccessToken {
		newResources.tokenGen = &TokenGenerator{
			Scopes: input.scopes,
		}
	}

	// Construct new impersonated account
	a := &ImpersonatedAccount{
		Name:             input.name,
		SecretType:       input.secretType,
		ServiceAccountId: acctId,
		TokenScopes:      input.scopes,
	}

	// Save to storage.
	if err := a.save(ctx, req.Storage); err != nil {
		return err
	}

	return err
}

func (b *backend) updateImpersonatedAccount(ctx context.Context, req *logical.Request, a *ImpersonatedAccount, updateInput *inputParams) (warnings []string, err error) {
	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return nil, err
	}

	_, err = b.getServiceAccount(iamAdmin, &a.ServiceAccountId)
	if err != nil {
		if isGoogleAccountNotFoundErr(err) {
			return nil, fmt.Errorf("unable to update impersonated account, could not find service account %q", a.ResourceName())
		}
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to create impersonated account, could not confirm service account %q exists: {{err}}", a.ResourceName()), err)
	}

	madeChange := false

	if a.SecretType == "access_token" {
		if !strutil.EquivalentSlices(updateInput.scopes, a.TokenScopes) {
			b.Logger().Debug("detected scopes change, updating scopes for impersonated account")
			a.TokenScopes = updateInput.scopes
			madeChange = true
		}
	}

	if !madeChange {
		return []string{"no changes to bindings or token_scopes detected, no update needed"}, nil
	}

	if err := a.save(ctx, req.Storage); err != nil {
		return nil, err
	}

	return
}
