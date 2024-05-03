// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
)

func TestPolicyToDataset(t *testing.T) {
	policy, expectedDataset := getTestFixtures()
	actualDataset, err := policyAsDataset(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !datasetEq(actualDataset, expectedDataset) {
		t.Fatalf("%v should be equal to %v", actualDataset, expectedDataset)
	}
}

func TestDatasetToPolicy(t *testing.T) {
	expectedPolicy, ds := getTestFixtures()
	actualPolicy := datasetAsPolicy(ds)
	if !policyEq(actualPolicy, expectedPolicy) {
		t.Fatalf("%v should be equal to %v", actualPolicy, expectedPolicy)
	}
}

func TestDatasetResource(t *testing.T) {
	expectedP := &Policy{
		Etag: "atag",
		Bindings: []*Binding{
			{
				Members: []string{"user:myuser@google.com", "serviceAccount:myserviceaccount@iam.gserviceaccount.com"},
				Role:    "roles/arole",
			},
			{
				Members: []string{"user:myuser@google.com", "group:mygroup@google.com"},
				Role:    "roles/anotherrole",
			},
		},
	}
	verifyDatasetResourceWithPolicy(t, expectedP)
}

func TestConditionalDatasetResource(t *testing.T) {
	p := &Policy{
		Etag:    "atag",
		Version: 3,
		Bindings: []*Binding{
			{
				Members: []string{"user:myuser@google.com", "serviceAccount:myserviceaccount@iam.gserviceaccount.com"},
				Role:    "roles/arole",
				Condition: &Condition{
					Title:       "test",
					Description: "",
					Expression:  "a==b",
				},
			},
			{
				Members: []string{"user:myuser@google.com"},
				Role:    "roles/anotherrole",
			},
		},
	}

	_, err := policyAsDataset(p)
	if err == nil {
		t.Fatalf("Datasets do not support conditions, but error was not triggered")
	}
}

func verifyDatasetResourceWithPolicy(t *testing.T, expectedP *Policy) {
	r := testResource()

	getR, err := constructRequest(r, &r.config.GetMethod, nil)
	if err != nil {
		t.Fatalf("Could not construct GetIamPolicyRequest: %v", err)
	}
	expectedURLBase := "https://bigquery.googleapis.com/bigquery/v2/projects/project/datasets/dataset"
	if getR.URL.String() != expectedURLBase {
		t.Fatalf("expected get request URL %s, got %s", expectedURLBase, getR.URL.String())
	}
	if getR.Method != "GET" {
		t.Fatalf("expected get request method %s, got %s", "GET", getR.Method)
	}
	if getR.Body != nil {
		data, err := ioutil.ReadAll(getR.Body)
		t.Fatalf("expected nil get body, actual non-nil body.Read returns %s %v", string(data), err)
	}

	ds, err := policyAsDataset(expectedP)
	if err != nil {
		t.Fatalf("Could not convert policy to dataset: %v", err)
	}

	jsonP, err := json.Marshal(ds)
	if err != nil {
		t.Fatalf("Could not json marshal expected policy: %v", err)
	}

	reqJson := fmt.Sprintf(r.config.SetMethod.RequestFormat, jsonP)
	if !json.Valid([]byte(reqJson)) {
		t.Fatalf("Could not format expected policy: %v", err)
	}

	setR, err := constructRequest(r, &r.config.SetMethod, strings.NewReader(reqJson))
	if err != nil {
		t.Fatalf("Could not construct SetIamPolicyRequest: %v", err)
	}

	if setR.URL.String() != expectedURLBase {
		t.Fatalf("expected set request URL %s, got %s", expectedURLBase, setR.URL.String())
	}
	if setR.Method != "PATCH" {
		t.Fatalf("expected set request method %s, got %s", "PATCH", setR.Method)
	}
	if setR.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected `Content Type = application/json` header in set request, headers: %+v", setR.Header)
	}
	if setR.Body == nil {
		t.Fatalf("expected non-nil set body, actually nil")
	}
	data, err := ioutil.ReadAll(setR.Body)
	if err != nil {
		t.Fatalf("unable to read data from set request: %v", err)
	}

	actual := struct {
		D *Dataset `json:"access,omitempty"`
		P *Policy  `json:"policy,omitempty"`
	}{}
	if err := json.Unmarshal(data, &actual.D); err != nil {
		t.Fatalf("unable to read policy from set request body: %v", err)
	}
	actual.P = datasetAsPolicy(actual.D)
	if actual.P.Etag != expectedP.Etag {
		t.Fatalf("mismatch set request policy, expected %s, got %s", expectedP.Etag, actual.P.Etag)
	}

	if len(actual.P.Bindings) != len(expectedP.Bindings) {
		t.Fatalf("mismatch set request policy bindings length, expected %+v, got %+v", expectedP.Bindings, actual.P.Bindings)
	}

	if !policyEq(expectedP, actual.P) {
		exBytes, _ := json.Marshal(expectedP)
		acBytes, _ := json.Marshal(actual.P)
		t.Fatalf("Expected policy %v. Got policy %v", string(exBytes), string(acBytes))
	}
}

// Necessary due to using a map to convert between dataset/policy
// since maps do not retain order
func policyEq(p1 *Policy, p2 *Policy) bool {
	sort.SliceStable(p1.Bindings, func(i, j int) bool { return p1.Bindings[i].Role < p1.Bindings[j].Role })
	sort.SliceStable(p2.Bindings, func(i, j int) bool { return p2.Bindings[i].Role < p2.Bindings[j].Role })
	return reflect.DeepEqual(p1, p2)
}

func datasetEq(d1 *Dataset, d2 *Dataset) bool {
	sort.SliceStable(d1.Access, func(i, j int) bool { return d1.Access[i].Role < d1.Access[j].Role })
	sort.SliceStable(d2.Access, func(i, j int) bool { return d2.Access[i].Role < d2.Access[j].Role })
	return reflect.DeepEqual(*d1, *d2)
}

func getTestFixtures() (*Policy, *Dataset) {
	policy := &Policy{
		Etag: "atag",
		Bindings: []*Binding{
			&Binding{
				Members: []string{
					"serviceAccount:foo@my-projectiam.gserviceaccount.com",
					"serviceAccount:bar@my-projectiam.gserviceaccount.com",
				},
				Role: "roles/bigquery.dataViewer",
			},
			&Binding{
				Members: []string{
					"serviceAccount:baz@my-projectiam.gserviceaccount.com",
				},
				Role: "roles/bigquery.dataOwner",
			},
		},
	}
	ds := &Dataset{
		Etag: "atag",
		Access: []*AccessBinding{
			&AccessBinding{
				Role:        "roles/bigquery.dataViewer",
				UserByEmail: "foo@my-projectiam.gserviceaccount.com",
			},
			&AccessBinding{
				Role:        "roles/bigquery.dataViewer",
				UserByEmail: "bar@my-projectiam.gserviceaccount.com",
			},
			&AccessBinding{
				Role:        "roles/bigquery.dataOwner",
				UserByEmail: "baz@my-projectiam.gserviceaccount.com",
			},
		},
	}
	return policy, ds
}

func testResource() *DatasetResource {
	return &DatasetResource{
		relativeId: &gcputil.RelativeResourceName{
			Name:    "datasets",
			TypeKey: "projects/datasets",
			IdTuples: map[string]string{
				"projects": "project",
				"datasets": "dataset",
			},
			OrderedCollectionIds: []string{"projects", "datasets"},
		},
		config: &RestResource{
			Name:                      "datasets",
			TypeKey:                   "projects/datasets",
			Service:                   "bigquery",
			IsPreferredVersion:        true,
			Parameters:                []string{"resource"},
			CollectionReplacementKeys: map[string]string{},
			GetMethod: RestMethod{
				HttpMethod: "GET",
				BaseURL:    "https://bigquery.googleapis.com",
				Path:       "bigquery/v2/{+resource}",
			},
			SetMethod: RestMethod{
				HttpMethod:    "PATCH",
				BaseURL:       "https://bigquery.googleapis.com",
				Path:          "bigquery/v2/{+resource}",
				RequestFormat: "%s",
			},
		},
	}
}
