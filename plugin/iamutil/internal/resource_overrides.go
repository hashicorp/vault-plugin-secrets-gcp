// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
)

var resourceOverrides = map[string]map[string]map[string]iamutil.RestResource{
	"projects/datasets": {
		"bigquery": {
			"v2": iamutil.RestResource{
				Name:                      "datasets",
				TypeKey:                   "projects/datasets",
				Service:                   "bigquery",
				IsPreferredVersion:        true,
				Parameters:                []string{"resource"},
				CollectionReplacementKeys: map[string]string{},
				GetMethod: iamutil.RestMethod{
					HttpMethod: "GET",
					BaseURL:    "https://bigquery.googleapis.com",
					Path:       "bigquery/v2/{+resource}",
				},
				SetMethod: iamutil.RestMethod{
					HttpMethod: "PATCH",
					BaseURL:    "https://bigquery.googleapis.com",
					// NOTE: the bigquery portion of the path needs to be in
					// the version since googleapis removes it from the
					// BaseURL when resolving
					Path:          "bigquery/v2/{+resource}",
					RequestFormat: "%s",
				},
			},
		},
	},
	"projects/datasets/tables": {
		"bigquery": {
			"v2": iamutil.RestResource{
				Name:                      "tables",
				TypeKey:                   "projects/datasets/tables",
				Service:                   "bigquery",
				IsPreferredVersion:        true,
				Parameters:                []string{"resource"},
				CollectionReplacementKeys: map[string]string{},
				GetMethod: iamutil.RestMethod{
					HttpMethod: "GET",
					BaseURL:    "https://bigquery.googleapis.com",
					Path:       "bigquery/v2/{+resource}:getIamPolicy",
				},
				SetMethod: iamutil.RestMethod{
					HttpMethod: "PATCH",
					BaseURL:    "https://bigquery.googleapis.com",
					// NOTE: the bigquery portion of the path needs to be in
					// the version since googleapis removes it from the
					// BaseURL when resolving
					Path:          "bigquery/v2/{+resource}:setIamPolicy",
					RequestFormat: `{"policy": %s}`,
				},
			},
		},
	},
	"projects/datasets/routines": {
		"bigquery": {
			"v2": iamutil.RestResource{
				Name:                      "routines",
				TypeKey:                   "projects/datasets/routines",
				Service:                   "bigquery",
				IsPreferredVersion:        true,
				Parameters:                []string{"resource"},
				CollectionReplacementKeys: map[string]string{},
				GetMethod: iamutil.RestMethod{
					HttpMethod: "GET",
					BaseURL:    "https://bigquery.googleapis.com",
					Path:       "bigquery/v2/{+resource}:getIamPolicy",
				},
				SetMethod: iamutil.RestMethod{
					HttpMethod: "PATCH",
					BaseURL:    "https://bigquery.googleapis.com",
					// NOTE: the bigquery portion of the path needs to be in
					// the version since googleapis removes it from the
					// BaseURL when resolving
					Path:          "bigquery/v2/{+resource}:setIamPolicy",
					RequestFormat: `{"policy": %s}`,
				},
			},
		},
	},
}

var resourceSkips = map[string]map[string]struct{}{
	"poly":            {"v1": {}},      // Advertised as available at https://poly.googleapis.com/$discovery/rest?alt=json&prettyPrint=false&version=v1, but returns a 502
	"realtimebidding": {"v1alpha": {}}, // Advertised as available at https://realtimebidding.googleapis.com/$discovery/rest?alt=json&prettyPrint=false&version=v1alpha, but returns a 404
}
