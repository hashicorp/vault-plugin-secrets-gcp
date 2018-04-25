//go:generate go run internal/generate_iam.go
package iamutil

import (
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"net/url"
	"strings"
)

const (
	resourceParsingErrorTmpl = `invalid resource "%s": %v`
	errorMultipleServices    = `please provide a self-link or full resource name for non-service-unique resource type`
	errorMultipleVersions    = `please provide a self-link with version instead; only non-preferred versions of this resource have IAM resource`
)

// IamResourceParser handles parsing resource ID and REST
// config from a given resource ID or name.
type IamResourceParser interface {
	Parse(string) (IamResource, error)
}

// GeneratedResources implements IamResourceParser - a value
// is generated using internal/generate_iam.go
type GeneratedResources map[string]map[string]map[string]IamRestResource

func getResourceFromVersions(rawName string, versionMap map[string]IamRestResource) (*IamRestResource, error) {
	for _, config := range versionMap {
		if config.IsPreferredVersion || len(versionMap) == 1 {
			return &config, nil
		}
	}
	return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, errorMultipleVersions)
}

func (apis GeneratedResources) GetRestConfig(rawName string, relName *gcputil.RelativeResourceName, service string, prefix string) (*IamRestResource, error) {
	serviceMap, ok := apis[relName.TypeKey]
	if !ok {
		return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, fmt.Errorf("unsupported resource type: %s", relName.TypeKey))
	}

	if len(prefix) > 0 {
		for _, versionMap := range serviceMap {
			for _, config := range versionMap {
				if strings.HasPrefix(config.GetMethod.BaseURL+config.GetMethod.Path, prefix) {
					return &config, nil
				}
			}
		}
		return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, fmt.Errorf("unsupported service/version for resource with prefix %s", prefix))
	} else if len(service) > 0 {
		versionMap, ok := serviceMap[service]
		if !ok {
			return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, fmt.Errorf("unsupported service %s for resource %s", service, relName.TypeKey))
		}

		return getResourceFromVersions(rawName, versionMap)
	} else if len(serviceMap) == 1 {
		for _, versionMap := range serviceMap {
			return getResourceFromVersions(rawName, versionMap)
		}
	}
	return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, errorMultipleServices)
}

func (apis GeneratedResources) Parse(rawName string) (IamResource, error) {
	rUrl, err := url.Parse(rawName)
	if err != nil {
		return nil, fmt.Errorf(`resource "%s" is invalid URI`, rawName)
	}

	var relName *gcputil.RelativeResourceName
	var prefix, service string
	if rUrl.Scheme != "" {
		selfLink, err := gcputil.ParseProjectResourceSelfLink(rawName)
		if err != nil {
			return nil, err
		}
		relName = selfLink.RelativeResourceName
		prefix = selfLink.Prefix
	} else if rUrl.Host != "" {
		fullName, err := gcputil.ParseFullResourceName(rawName)
		if err != nil {
			return nil, err
		}
		relName = fullName.RelativeResourceName
		service = fullName.Service
	} else {
		relName, err = gcputil.ParseRelativeName(rawName)
		if err != nil {
			return nil, err
		}
	}

	if relName == nil {
		return nil, fmt.Errorf(resourceParsingErrorTmpl, rawName, "unable to parse relative name")
	}

	cfg, err := apis.GetRestConfig(rawName, relName, prefix, service)
	if err != nil {
		return nil, err
	}
	return &parsedIamResource{
		relativeId: relName,
		config:     cfg,
	}, nil
}
