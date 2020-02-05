package iamutil

import (
	"fmt"
	"strings"
)

// NOTE: BigQuery does not conform to the typical REST for IAM policies
// instead it has an access array with bindings on the dataset
// object. https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets#Dataset
type AccessBinding struct {
	Role        string `json:"role,omitempty"`
	UserByEmail string `json:"userByEmail,omitempty"`
}

type Dataset struct {
	Access []*AccessBinding `json:"access,omitempty"`
}

func (p *Policy) AsDataset() Dataset {
	dataset := Dataset{}
	if p == nil {
		return dataset
	}
	for _, binding := range p.Bindings {
		for _, member := range binding.Members {
			var email string
			memberSplit := strings.Split(member, ":")
			if len(memberSplit) == 2 {
				email = memberSplit[1]
			} else {
				email = member
			}

			if email != "" {
				dataset.Access = append(dataset.Access, &AccessBinding{
					Role:        binding.Role,
					UserByEmail: email,
				})
			}
		}
	}
	return dataset
}

func (ds *Dataset) AsPolicy() Policy {
	policy := Policy{}
	if ds == nil {
		return policy
	}
	bindingMap := make(map[string]*Binding)
	for _, accessBinding := range ds.Access {
		email := fmt.Sprintf("serviceAccount:%s", accessBinding.UserByEmail)
		if binding, ok := bindingMap[accessBinding.Role]; ok {
			binding.Members = append(binding.Members, email)
		} else {
			bindingMap[accessBinding.Role] = &Binding{
				Role:    accessBinding.Role,
				Members: []string{email},
			}
		}
	}
	for k := range bindingMap {
		policy.Bindings = append(policy.Bindings, bindingMap[k])
	}
	return policy
}

func (r *parsedIamResource) IsBigqueryResource() bool {
	return r.config.TypeKey == "projects/datasets" && r.config.Service == "bigquery"
}
