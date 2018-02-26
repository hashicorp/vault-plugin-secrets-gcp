package iamutil

import (
	"fmt"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
)

const (
	serviceAccountMemberTmpl = "serviceAccount:%s"
)

type Policy struct {
	Bindings []*Binding `json:"bindings,omitempty"`
	Etag     string     `json:"etag,omitempty"`
}

type Binding struct {
	Members []string `json:"members,omitempty"`
	Role    string   `json:"role,omitempty"`
}

type PolicyDelta struct {
	Roles util.StringSet
	Email string
}

func (p *Policy) AddBindings(toAdd *PolicyDelta) (changed bool, updated *Policy) {
	return p.ChangedBindings(toAdd, nil)
}

func (p *Policy) RemoveBindings(toRemove *PolicyDelta) (changed bool, updated *Policy) {
	return p.ChangedBindings(nil, toRemove)
}

func (p *Policy) ChangedBindings(toAdd *PolicyDelta, toRemove *PolicyDelta) (changed bool, updated *Policy) {
	if toAdd == nil && toRemove == nil {
		return false, p
	}
	changed = false

	newBindings := make([]*Binding, 0, len(p.Bindings))
	alreadyAdded := make(util.StringSet)

	for _, bind := range p.Bindings {
		memberSet := util.ToSet(bind.Members)

		if toAdd != nil {
			if _, ok := toAdd.Roles[bind.Role]; ok {
				changed = true
				alreadyAdded[bind.Role] = struct{}{}
				memberSet[fmt.Sprintf(serviceAccountMemberTmpl, toAdd.Email)] = struct{}{}
			}
		}

		if toRemove != nil {
			if _, ok := toRemove.Roles[bind.Role]; ok {
				changed = true
				delete(memberSet, fmt.Sprintf(serviceAccountMemberTmpl, toRemove.Email))
			}
		}

		if len(memberSet) > 0 {
			newBindings = append(newBindings, &Binding{
				Role:    bind.Role,
				Members: memberSet.ToSlice(),
			})
		}
	}

	if toAdd != nil {
		for r := range toAdd.Roles {
			if _, ok := alreadyAdded[r]; !ok {
				changed = true
				newBindings = append(newBindings, &Binding{
					Role:    r,
					Members: []string{fmt.Sprintf(serviceAccountMemberTmpl, toAdd.Email)},
				})
			}
		}
	}

	if changed {
		return true, &Policy{
			Bindings: newBindings,
			Etag:     p.Etag,
		}
	}
	return false, p
}
