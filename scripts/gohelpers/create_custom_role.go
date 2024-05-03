// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"golang.org/x/oauth2"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

var defaultScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
}

var iamAdminPermissions = []string{
	"iam.serviceAccounts.create",
	"iam.serviceAccounts.delete",
	"iam.serviceAccounts.get",
	"iam.serviceAccounts.list",
	"iam.serviceAccountKeys.create",
	"iam.serviceAccountKeys.delete",
	"iam.serviceAccountKeys.get",
	"iam.serviceAccountKeys.list",
	"iam.serviceAccounts.update",
	"iam.serviceAccounts.getIamPolicy",
	"iam.serviceAccounts.setIamPolicy",
}

func main() {
	var roleName, project, org, creds, stage string
	flag.StringVar(&roleName, "name", "vaultSecretsAdmin", "name of the custom IAM role to create")
	flag.StringVar(&project, "project", "", "Name of the GCP project to create custom IAM role under")
	flag.StringVar(&org, "organization", "", "Name of the GCP organization to create custom IAM role under")
	flag.StringVar(&creds, "credentials", "", "Either JSON contents for a GCP credentials JSON file or '@path/to/creds.json' (note '@' prepended)")
	flag.StringVar(&stage, "stage", "ALPHA", "Launch stage for role (ALPHA/BETA/GA)")
	flag.Parse()

	if err := validateFlags(roleName, project, org, stage); err != nil {
		log.Printf("unable to get client: %s\n", err)
		os.Exit(1)
	}

	iamAdmin, err := getIamClient(creds)
	if err != nil {
		log.Printf("unable to get client: %s\n", err)
		os.Exit(1)
	}

	var resource string
	if project != "" {
		resource = fmt.Sprintf("projects/%s", project)
	} else {
		resource = fmt.Sprintf("organizations/%s", org)
	}
	addPerms, err := getIamPermissions(iamAdmin, resource)
	if err != nil {
		log.Printf("unable to create role: %v", err)
		os.Exit(1)
	}

	req := &iam.CreateRoleRequest{
		Role: &iam.Role{
			Description:         "Role that allow Vault GCP secrets engine to manage IAM service accounts and assign IAM policies",
			Stage:               stage,
			IncludedPermissions: append(addPerms, iamAdminPermissions...),
		},
		RoleId: roleName,
	}

	var r *iam.Role
	if project != "" {
		r, err = iamAdmin.Projects.Roles.Create(fmt.Sprintf("projects/%s", project), req).Do()
	}
	if org != "" {
		r, err = iamAdmin.Organizations.Roles.Create(fmt.Sprintf("organizations/%s", org), req).Do()
	}
	if err != nil {
		log.Printf("unable to create role: %v", err)
		os.Exit(1)
	}

	log.Printf("Success! Created role %s\n", r.Name)
}

func validateFlags(roleName, project, organization, stage string) error {
	if project == "" && organization == "" {
		return fmt.Errorf("exactly one of project or organization must be specified (role will be scoped to provided value)")
	}

	if project != "" && organization != "" {
		return fmt.Errorf("please specify only project or organization (role will be scoped to provided value)")
	}

	if roleName == "" {
		return fmt.Errorf("flag 'name' is required for name of role set")
	}

	switch stage {
	case "ALPHA", "BETA", "GA", "":
		break
	default:
		return fmt.Errorf("invalid launch stage: %s", stage)
	}

	return nil
}

func getIamClient(creds string) (*iam.Service, error) {
	if len(creds) > 1 && creds[0] == '@' {
		d, err := ioutil.ReadFile(creds[1:])
		if err != nil {
			return nil, errwrap.Wrapf(fmt.Sprintf("unable to read contents of file '%s': {{err}}", creds[1:]), err)
		}
		creds = string(d)
	}

	_, tknSrc, err := gcputil.FindCredentials(creds, context.Background(), defaultScopes...)
	if err != nil {
		return nil, err
	}

	httpC := oauth2.NewClient(context.Background(), tknSrc)
	return iam.NewService(context.Background(), option.WithHTTPClient(httpC))
}

func getIamPermissions(iamAdmin *iam.Service, resource string) ([]string, error) {
	fullName := fmt.Sprintf("//cloudresourcemanager.googleapis.com/%s", resource)

	nextToken, allPerms, err := getPermissions(iamAdmin, "", fullName)
	if err != nil {
		return nil, err
	}

	for len(nextToken) > 0 {
		var perms []string
		nextToken, perms, err = getPermissions(iamAdmin, nextToken, fullName)
		if err != nil {
			return nil, err
		}
		allPerms = append(allPerms, perms...)
	}

	return allPerms, nil
}

func getPermissions(iamAdmin *iam.Service, nextPageToken, resource string) (string, []string, error) {
	req := &iam.QueryTestablePermissionsRequest{
		FullResourceName: resource,
		PageToken:        nextPageToken,
	}
	resp, err := iamAdmin.Permissions.QueryTestablePermissions(req).Do()
	if err != nil {
		return "", nil, err
	}

	permissions := make([]string, 0, len(resp.Permissions))
	for _, perm := range resp.Permissions {
		if perm.ApiDisabled || perm.CustomRolesSupportLevel == "NOT_SUPPORTED" {
			continue
		}
		if strings.HasSuffix(perm.Name, ".getIamPolicy") || strings.HasSuffix(perm.Name, ".setIamPolicy") {
			permissions = append(permissions, perm.Name)
		}
	}
	return resp.NextPageToken, permissions, nil
}
