// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
)

func TestIamResource(t *testing.T) {
	r := &IamResource{
		relativeId: &gcputil.RelativeResourceName{
			Name:    "b",
			TypeKey: "f/b",
			IdTuples: map[string]string{
				"f": "foo1",
				"b": "bar2",
			},
			OrderedCollectionIds: []string{"f", "b"},
		},
		config: &RestResource{
			Name:               "b",
			TypeKey:            "f/b",
			Service:            "agcpservice",
			IsPreferredVersion: true,
			GetMethod: RestMethod{
				HttpMethod: "GET",
				BaseURL:    "https://agcpservice.googleapis.com/v1/",
				Path:       "f/{foo}/b/{resource}:getIamPolicy",
			},
			SetMethod: RestMethod{
				HttpMethod:    "POST",
				BaseURL:       "https://agcpservice.googleapis.com/v1/",
				Path:          "f/{foo}/b/{resource}:setIamPolicy",
				RequestFormat: `{"policy":%s}`,
			},
			Parameters: []string{"foo", "resource"},
			CollectionReplacementKeys: map[string]string{
				"b":    "resource",
				"bars": "resource",
				"f":    "foo",
				"foos": "foo",
			},
		},
	}

	getR, err := constructRequest(r, &r.config.GetMethod, nil)
	if err != nil {
		t.Fatalf("Could not construct GetIamPolicyRequest: %v", err)
	}
	expectedURLBase := "https://agcpservice.googleapis.com/v1/f/foo1/b/bar2"
	if getR.URL.String() != expectedURLBase+":getIamPolicy" {
		t.Fatalf("expected get request URL %s, got %s", expectedURLBase+":getIamPolicy", getR.URL.String())
	}
	if getR.Method != "GET" {
		t.Fatalf("expected get request method %s, got %s", "GET", getR.Method)
	}
	if getR.Body != nil {
		data, err := ioutil.ReadAll(getR.Body)
		t.Fatalf("expected nil get body, actual non-nil body.Read returns %s %v", string(data), err)
	}

	expectedP := &Policy{
		Etag: "atag",
		Bindings: []*Binding{
			{
				Members: []string{"user:myuser@google.com", "serviceAccount:myserviceaccount@iam.gserviceaccount.com"},
				Role:    "roles/arole",
			},
			{
				Members: []string{"user:myuser@google.com"},
				Role:    "roles/anotherrole",
			},
		},
	}

	jsonP, err := json.Marshal(expectedP)
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

	if setR.URL.String() != expectedURLBase+":setIamPolicy" {
		t.Fatalf("expected set request URL %s, got %s", expectedURLBase+":setIamPolicy", getR.URL.String())
	}
	if setR.Method != "POST" {
		t.Fatalf("expected set request method %s, got %s", "POST", getR.Method)
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
		P *Policy `json:"policy,omitempty"`
	}{}
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatalf("unable to read policy from set request body: %v", err)
	}
	if actual.P.Etag != expectedP.Etag {
		t.Fatalf("mismatch set request policy, expected %s, got %s", expectedP.Etag, actual.P.Etag)
	}

	if len(actual.P.Bindings) != len(expectedP.Bindings) {
		t.Fatalf("mismatch set request policy bindings length, expected %+v, got %+v", expectedP.Bindings, actual.P.Bindings)
	}

	for i, expectB := range expectedP.Bindings {
		actualB := actual.P.Bindings[i]
		if expectB.Role != actualB.Role {
			t.Errorf("expected bindings[%d] to have role %s, got %s", i, expectB.Role, actualB.Role)
		}
		if len(expectB.Members) != len(actualB.Members) {
			t.Errorf("expected bindings[%d] to have members %+v, got %+v", i, expectB.Members, actualB.Members)
		}
		for memberI, expectM := range expectB.Members {
			if expectM != actualB.Members[memberI] {
				t.Errorf("expected bindings[%d], members[%d] to be %s, got %s", i, memberI, expectM, actualB.Members[memberI])
			}
		}
	}
}

func TestConditionalIamResource(t *testing.T) {
	r := &IamResource{
		relativeId: &gcputil.RelativeResourceName{
			Name:    "projects",
			TypeKey: "cloudresourcemanager/projects",
			IdTuples: map[string]string{
				"projects": "project",
			},
			OrderedCollectionIds: []string{"cloudresourcemanager", "projects"},
		},
		config: &RestResource{
			Name:               "projects",
			TypeKey:            "cloudresourcemanager/projects",
			Service:            "cloudresourcemanager",
			IsPreferredVersion: true,
			GetMethod: RestMethod{
				HttpMethod: "GET",
				BaseURL:    "https://cloudresourcemanager.googleapis.com/v1/",
				Path:       "projects/{resource}:getIamPolicy",
			},
			SetMethod: RestMethod{
				HttpMethod:    "POST",
				BaseURL:       "https://cloudresourcemanager.googleapis.com/v1/",
				Path:          "projects/{resource}:setIamPolicy",
				RequestFormat: `{"policy":%s}`,
			},
			Parameters: []string{"resource"},
			CollectionReplacementKeys: map[string]string{
				"projects": "resource"},
		},
	}

	getR, err := constructRequest(r, &r.config.GetMethod, nil)
	if err != nil {
		t.Fatalf("Could not construct GetIamPolicyRequest: %v", err)
	}
	expectedURLBase := "https://cloudresourcemanager.googleapis.com/v1/projects/project"
	if getR.URL.String() != expectedURLBase+":getIamPolicy" {
		t.Fatalf("expected get request URL %s, got %s", expectedURLBase+":getIamPolicy", getR.URL.String())
	}
	if getR.Method != "GET" {
		t.Fatalf("expected get request method %s, got %s", "GET", getR.Method)
	}
	if getR.Body == nil {
		t.Fatalf("expected non-nil get body")
	}
	data, err := ioutil.ReadAll(getR.Body)
	if err != nil {
		t.Fatalf("Error reading data from request body %v", err)
	}
	var body interface{}
	err = json.Unmarshal(data, &body)
	if err != nil {
		t.Fatalf("Error parsing json from request body %s %v", string(data), err)
	}
	reqBody, ok := body.(map[string]interface{})
	if !ok {
		t.Fatalf("Error asserting request body %s", string(data))
	}
	options, ok := reqBody["options"]
	if !ok {
		t.Fatalf("Couldn't find options in request body %s", string(data))
	}

	optionsMap, ok := options.(map[string]interface{})
	if !ok {
		t.Fatalf("Error asserting options in request body %s", string(data))
	}

	requestedPolicyVersion, ok := optionsMap["requestedPolicyVersion"]
	if !ok {
		t.Fatalf("Couldn't find requestedPolicytVersion in options in request body %s", string(data))
	}

	version, ok := requestedPolicyVersion.(float64)
	if !ok {
		t.Fatalf("Error asserting requestedPolicyVersion in request body %s", string(data))
	}

	if version != 3 {
		t.Fatalf("requestedPolicyVersion is not 3 in request body %s", string(data))
	}

	expectedP := &Policy{
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

	jsonP, err := json.Marshal(expectedP)
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

	if setR.URL.String() != expectedURLBase+":setIamPolicy" {
		t.Fatalf("expected set request URL %s, got %s", expectedURLBase+":setIamPolicy", getR.URL.String())
	}
	if setR.Method != "POST" {
		t.Fatalf("expected set request method %s, got %s", "POST", getR.Method)
	}
	if setR.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected `Content Type = application/json` header in set request, headers: %+v", setR.Header)
	}
	if setR.Body == nil {
		t.Fatalf("expected non-nil set body, actually nil")
	}
	data, err = ioutil.ReadAll(setR.Body)
	if err != nil {
		t.Fatalf("unable to read data from set request: %v", err)
	}

	actual := struct {
		P *Policy `json:"policy,omitempty"`
	}{}
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatalf("unable to read policy from set request body: %v", err)
	}
	if actual.P.Etag != expectedP.Etag {
		t.Fatalf("mismatch set request policy, expected %s, got %s", expectedP.Etag, actual.P.Etag)
	}

	if len(actual.P.Bindings) != len(expectedP.Bindings) {
		t.Fatalf("mismatch set request policy bindings length, expected %+v, got %+v", expectedP.Bindings, actual.P.Bindings)
	}

	for i, expectB := range expectedP.Bindings {
		actualB := actual.P.Bindings[i]
		if expectB.Role != actualB.Role {
			t.Errorf("expected bindings[%d] to have role %s, got %s", i, expectB.Role, actualB.Role)
		}
		if len(expectB.Members) != len(actualB.Members) {
			t.Errorf("expected bindings[%d] to have members %+v, got %+v", i, expectB.Members, actualB.Members)
		}
		for memberI, expectM := range expectB.Members {
			if expectM != actualB.Members[memberI] {
				t.Errorf("expected bindings[%d], members[%d] to be %s, got %s", i, memberI, expectM, actualB.Members[memberI])
			}
		}
		if expectB.Condition != nil {
			if actualB.Condition == nil {
				t.Errorf("expected bindings[%d] to have condition %s, got %s", i, expectB.Condition, actualB.Condition)
			}
			if expectB.Condition.Title != actualB.Condition.Title {
				t.Errorf("expected bindings[%d] to have condition titled %s, got %s", i, expectB.Condition.Title, actualB.Condition.Title)
			}
			if expectB.Condition.Description != actualB.Condition.Description {
				t.Errorf("expected bindings[%d] to have condition description %s, got %s", i, expectB.Condition.Description, actualB.Condition.Description)
			}
			if expectB.Condition.Expression != actualB.Condition.Expression {
				t.Errorf("expected bindings[%d] to have condition expression %s, got %s", i, expectB.Condition.Expression, actualB.Condition.Expression)
			}
		}
	}
}
