package iamutil

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
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

// NOTE: DatasetResource implements IamResource.
// This is because bigquery datasets have their own
// ACLs instead of an IAM policy
type DatasetResource struct {
	relativeId *gcputil.RelativeResourceName
	config     *RestResource
}

func (r *DatasetResource) GetConfig() *RestResource {
	return r.config
}

func (r *DatasetResource) GetRelativeId() *gcputil.RelativeResourceName {
	return r.relativeId
}

func (r *DatasetResource) GetIamPolicy(ctx context.Context, h *ApiHandle) (*Policy, error) {
	var dataset Dataset
	if err := h.DoGetRequest(ctx, r, &dataset); err != nil {
		return nil, errwrap.Wrapf("unable to get BigQuery Dataset ACL: {{err}}", err)
	}
	p := dataset.AsPolicy()
	return &p, nil
}

func (r *DatasetResource) SetIamPolicy(ctx context.Context, h *ApiHandle, p *Policy) (*Policy, error) {
	var jsonP []byte
	jsonP, err := json.Marshal(p.AsDataset())
	if err != nil {
		return nil, err
	}
	reqJson := fmt.Sprintf(r.config.SetMethod.RequestFormat, jsonP)
	if !json.Valid([]byte(reqJson)) {
		return nil, fmt.Errorf("request format from generated BigQuery Dataset config invalid JSON: %s", reqJson)
	}

	var dataset Dataset
	if err := h.DoSetRequest(ctx, r, strings.NewReader(reqJson), &dataset); err != nil {
		return nil, errwrap.Wrapf("unable to set BigQuery Dataset ACL: {{err}}", err)
	}
	policy := dataset.AsPolicy()

	return &policy, nil
}

func (p *Policy) AsDataset() Dataset {
	ds := Dataset{}
	if p == nil {
		return ds
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
				ds.Access = append(ds.Access, &AccessBinding{
					Role:        binding.Role,
					UserByEmail: email,
				})
			}
		}
	}
	return ds
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
