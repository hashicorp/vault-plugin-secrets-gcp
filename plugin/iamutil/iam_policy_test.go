package iamutil

import (
	"testing"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
)

func TestConditionsAfterIamPolicyUpdate(t *testing.T) {
	p := &Policy{
		Version: 3,
		Etag:    "atag",
		Bindings: []*Binding{
			{
				Members: []string{"user:myuser@google.com", "serviceAccount:myserviceaccount@iam.gserviceaccount.com"},
				Role:    "roles/arole",
			},
			{
				Members: []string{"user:myuser@google.com"},
				Role:    "roles/anotherrole",
				Condition: &Condition{
					Title:       "Temporary",
					Description: "some description",
					Expression:  "some expression",
				},
			},
			{
				Members: []string{"user:myuser@google.com"},
				Role:    "roles/yetanotherrole",
				Condition: &Condition{
					Title:       "Temporary",
					Description: "some description",
					Expression:  "some expression",
				},
			},
		},
	}

	d := &PolicyDelta{
		Roles: util.ToSet([]string{"roles/brole", "roles/crole"}),
		Email: "myuser@google.com",
	}

	_, np := p.AddBindings(d)

	conditions_before := 0
	for _, binding := range p.Bindings {
		if binding.Condition != nil {
			conditions_before += 1
		}
	}

	conditions_after := 0
	for _, binding := range np.Bindings {
		if binding.Condition != nil {
			conditions_after += 1
		}
	}

	if conditions_after != conditions_before {
		t.Fatalf("number of conditions changed after adding bindings: before - %v now - %v", conditions_before, conditions_after)
	}

	_, np = p.RemoveBindings(d)

	conditions_after = 0
	for _, binding := range np.Bindings {
		if binding.Condition != nil {
			conditions_after += 1
		}
	}

	if conditions_after != conditions_before {
		t.Fatalf("number of conditions changed after removing bindings: before - %v now - %v", conditions_before, conditions_after)
	}
}
