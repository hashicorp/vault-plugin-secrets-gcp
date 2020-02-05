package iamutil

import (
	"encoding/json"
	"testing"
)

func TestPolicyToDataset(t *testing.T) {
	policy, expectedDataset := getTestFixtures()
	expectedDatasetBytes, err := json.Marshal(expectedDataset)
	if err != nil {
		t.Fatal(err)
	}
	actualDataset := policy.AsDataset()
	actualDatasetBytes, err := json.Marshal(actualDataset)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualDatasetBytes) != string(expectedDatasetBytes) {
		t.Fatalf("%v should be equal to %v", string(actualDatasetBytes), string(expectedDatasetBytes))
	}
}

func TestDatasetToPolicy(t *testing.T) {
	expectedPolicy, dataset := getTestFixtures()
	expectedPolicyBytes, err := json.Marshal(expectedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	actualPolicy := dataset.AsPolicy()
	actualPolicyBytes, err := json.Marshal(actualPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualPolicyBytes) != string(expectedPolicyBytes) {
		t.Fatalf("%v should be equal to %v", string(actualPolicyBytes), string(expectedPolicyBytes))
	}
}

func getTestFixtures() (*Policy, *Dataset) {
	policy := &Policy{
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
	dataset := &Dataset{
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
	return policy, dataset
}
