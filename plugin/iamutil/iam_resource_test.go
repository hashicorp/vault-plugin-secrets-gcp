package iamutil

import (
	"encoding/json"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"io/ioutil"
	"testing"
)

func TestParsedIamResource(t *testing.T) {
	r := &parsedIamResource{
		relativeId: &gcputil.RelativeResourceName{
			Name:    "b",
			TypeKey: "f/b",
			IdTuples: map[string]string{
				"f": "foo1",
				"b": "bar2",
			},
			OrderedCollectionIds: []string{"f", "b"},
		},
		config: &IamRestResource{
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

	getR, err := r.GetIamPolicyRequest()
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
				Members: []string{"user:myuser@google.com", "serviceAccount:myserviceaccount@iam.gserviceaccounts.com"},
				Role:    "roles/arole",
			},
			{
				Members: []string{"user:myuser@google.com"},
				Role:    "roles/anotherrole",
			},
		},
	}
	setR, err := r.SetIamPolicyRequest(expectedP)
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
