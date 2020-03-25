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
}
