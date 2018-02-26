package util

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"io/ioutil"
	"strings"
	"text/template"
)

func BindingsHCL(bindings map[string]StringSet) (string, error) {
	tpl, err := template.ParseGlob(bindingTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "main", bindings); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func ParseBindings(bindingsStr string, b64Encoded bool) (map[string]StringSet, error) {
	binds := bindingsStr

	if b64Encoded {
		decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(bindingsStr))
		decoded, err := ioutil.ReadAll(decoder)
		if err != nil {
			return nil, errors.New(`unable to base-64 decode string`)
		}
		binds = string(decoded)
	}

	root, err := hcl.Parse(binds)
	if err != nil {
		return nil, fmt.Errorf("unable to parse bindings: %v", err)
	}

	bindingLst, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("unable to parse bindings: does not contain a root object")
	}

	bindingsMap, err := parseBindingObjList(bindingLst)
	if err != nil {
		return nil, fmt.Errorf("unable to parse bindings: %v", err)
	}
	return bindingsMap, nil
}

func parseBindingObjList(topList *ast.ObjectList) (map[string]StringSet, error) {
	var err error

	bindings := make(map[string]StringSet)

	for _, item := range topList.Items {
		if len(item.Keys) != 2 {
			err = multierror.Append(err, fmt.Errorf("invalid resource item does not have ID on line %d", item.Assign.Line))
			continue
		}

		key := item.Keys[0].Token.Value().(string)
		if key != "resource" {
			err = multierror.Append(err, fmt.Errorf("invalid key '%s' (line %d)", key, item.Assign.Line))
			continue
		}

		resourceName := item.Keys[1].Token.Value().(string)
		_, ok := bindings[resourceName]
		if !ok {
			bindings[resourceName] = make(StringSet)
		}

		resourceList := item.Val.(*ast.ObjectType).List
		for _, rolesItem := range resourceList.Items {
			key := rolesItem.Keys[0].Token.Text
			switch key {
			case "roles":
				err = parseRoles(rolesItem, bindings[resourceName], err)
			default:
				err = multierror.Append(err, fmt.Errorf("invalid key '%s' in resource '%s' (line %d)", key, resourceName, item.Assign.Line))
				continue
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return bindings, nil
}

func parseRoles(item *ast.ObjectItem, roleSet StringSet, err error) error {
	lst, ok := item.Val.(*ast.ListType)
	if !ok {
		return multierror.Append(err, fmt.Errorf("roles must be a list (line %d)", item.Assign.Line))
	}

	for _, roleItem := range lst.List {
		role := roleItem.(*ast.LiteralType).Token.Value().(string)
		if !strings.HasPrefix(role, "roles/") {
			err = multierror.Append(err, fmt.Errorf("role '%s' must start with 'roles/' (line %d)", role, roleItem.Pos().Line))
			continue
		}
		roleSet.Add(role)
	}

	return err
}

const bindingTemplate = `
{{define "bindings" -}}
{{ range $resource,$roleStringSet := . -}}
resource "{{$resource}}" {
	roles = [
	{{- range $role := $roleStringSet -}}
		"{{ $role }}",
	{{ end -}}
	],
}
{{- end }}
`
