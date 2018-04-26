package iamutil

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/errwrap"
	"net/url"
)

func TestEnabledIamResources_RelativeName(t *testing.T) {
	enabledApis := GetEnabledIamResources()

	for resourceType, services := range generatedIamResources {
		testRelName := getFakeId(resourceType)

		var needsService = len(services) > 1
		var needsVersion bool
		if !needsService {
			for _, versions := range services {
				needsVersion = expectVersionError(versions)
				break
			}
		}

		resource, err := enabledApis.Parse(testRelName)
		if !needsService && !needsVersion {
			if err != nil {
				t.Errorf("failed to get resource for relative resource name %s (type: %s): %v", testRelName, resourceType, err)
			}
			if err = verifyResource(resourceType, resource.(*parsedIamResource)); err != nil {
				t.Errorf("could not verify resource for relative resource name %s: %v", testRelName, err)
			}
		} else if resource != nil || err == nil {
			t.Errorf("expected error for using relative resource name %s (type: %s), got resource:\n %v\n", testRelName, resourceType, resource)
			continue
		}
	}
}

func TestEnabledIamResources_FullName(t *testing.T) {
	enabledApis := GetEnabledIamResources()

	for resourceType, services := range generatedIamResources {
		for service, versions := range services {
			testFullName := fmt.Sprintf("//%s.googleapis.com/%s", service, getFakeId(resourceType))
			resource, err := enabledApis.Parse(testFullName)

			if !expectVersionError(versions) {
				if err != nil {
					t.Errorf("failed to get resource for full resource name %s (type: %s): %v", testFullName, resourceType, err)
					continue
				}
				if err = verifyResource(resourceType, resource.(*parsedIamResource)); err != nil {
					t.Errorf("could not verify resource for relative resource name %s: %v", testFullName, err)
					continue
				}
			} else if resource != nil || err == nil {
				t.Errorf("expected error for using full resource name %s (type: %s), got resource:\n %v\n", testFullName, resourceType, resource)
				continue
			}
		}
	}
}

func constructSelfLink(relName string, cfg IamRestResource) (string, error) {
	reqUrl := cfg.GetMethod.BaseURL + cfg.GetMethod.Path

	_, err := url.Parse(reqUrl)
	if err != nil {
		return "", fmt.Errorf("unexpected request URL in resource GetMethod - %s is not a URL", reqUrl)
	}

	fullResourceI := strings.Index(reqUrl, "/{+resource}")
	if fullResourceI >= 0 {
		return reqUrl[:fullResourceI] + relName, nil
	}

	endI := strings.Index(reqUrl, "/{")
	if endI < 1 {
		return "", fmt.Errorf("unexpected request URL in resource does not have parameter to be replaced: %s", reqUrl)
	}
	startI := strings.LastIndex(reqUrl, "/")
	if startI < 0 {
		return "", fmt.Errorf("unexpected request URL in resource does not have proper parameter to be replaced: %s", reqUrl)
	}
	return reqUrl[:startI] + relName, nil
}

func TestEnabledIamResources_SelfLink(t *testing.T) {
	enabledApis := GetEnabledIamResources()

	for resourceType, services := range generatedIamResources {
		for _, versions := range services {
			for _, cfg := range versions {
				relName := getFakeId(resourceType)
				testSelfLink, err := constructSelfLink(relName, cfg)
				if err != nil {
					t.Error(err)
					continue
				}
				isProjectLevel := strings.HasPrefix(relName, "projects/")
				if isProjectLevel && strings.HasSuffix(cfg.GetMethod.BaseURL, "projects/") {
					testSelfLink = cfg.GetMethod.BaseURL + strings.TrimPrefix(relName, "projects/")
				}

				resource, err := enabledApis.Parse(testSelfLink)
				if isProjectLevel {
					if err != nil {
						t.Errorf("failed to get resource for self link %s (type: %s): %v", testSelfLink, resourceType, err)
					}
					if err = verifyResource(resourceType, resource.(*parsedIamResource)); err != nil {
						t.Errorf("could not verify resource for self link %s: %v", testSelfLink, err)
					}
				} else if resource != nil || err == nil {
					t.Errorf("expected error for using self link %s (type: %s), got resource:\n %v\n", testSelfLink, resourceType, resource)
					continue
				}
			}
		}
	}
}

func expectVersionError(versions map[string]IamRestResource) bool {
	needsVersion := len(versions) > 1
	for _, cfg := range versions {
		needsVersion = needsVersion && !cfg.IsPreferredVersion
	}
	return needsVersion
}

func verifyHttpMethod(typeKey string, m *RestMethod) error {
	if len(m.Path) == 0 {
		return fmt.Errorf("empty http method path")
	}

	if m.BaseURL == "" {
		return fmt.Errorf("empty base url for method (typeKey %s)", typeKey)
	}
	if m.Path == "" {
		return fmt.Errorf("empty path for method (typeKey %s)", typeKey)
	}

	fullUrl := m.BaseURL + m.Path
	u, err := url.Parse(fullUrl)
	if err != nil {
		return fmt.Errorf("invalid method URL for resource %s: %s", typeKey, fullUrl)
	}
	if u.Scheme == "" {
		return fmt.Errorf("invalid method URL for resource %s is missing scheme: %s", typeKey, fullUrl)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid method URL for resource %s is missing host: %s", typeKey, fullUrl)
	}
	if u.Path == "" {
		return fmt.Errorf("invalid method URL for resource %s is missing path: %s", typeKey, fullUrl)
	}

	switch m.HttpMethod {
	case http.MethodGet:
	case http.MethodPost:
	case http.MethodPut:
		return nil
	default:
		return fmt.Errorf("unexpected HttpMethod %s", m.HttpMethod)
	}

	return nil
}

func TestIamEnabledResources_ValidateGeneratedConfig(t *testing.T) {
	for typeKey, services := range generatedIamResources {
		for service, versions := range services {
			for ver, cfg := range versions {
				if cfg.Service != service {
					t.Errorf("mismatch service config name '%s' for resources[%s][%s][%s]", cfg.Name, service, ver, typeKey)
				}

				if err := verifyHttpMethod(typeKey, &cfg.GetMethod); err != nil {
					t.Errorf("error with resource[%s][%s][%s].GetIamPolicy: %v", service, ver, typeKey, err)
				}
				if err := verifyHttpMethod(typeKey, &cfg.SetMethod); err != nil {
					t.Errorf("error with resource[%s][%s][%s].SetIamPolicy: %v", service, ver, typeKey, err)
				}
			}
		}
	}
}

func getFakeId(resourceType string) string {
	collectionIds := strings.Split(resourceType, "/")

	fakeId := ""
	for idx, cid := range collectionIds {
		fakeId += fmt.Sprintf("%s/aFakeId%d/", cid, idx)
	}
	return strings.Trim(fakeId, "/")
}

func verifyResource(rType string, resource *parsedIamResource) error {
	if resource.relativeId.TypeKey != rType {
		return fmt.Errorf("expected resource type %s, actual resource has different type %s", rType, resource.relativeId.TypeKey)
	}

	req, err := resource.GetIamPolicyRequest()
	if err != nil {
		return errwrap.Wrapf("unable to construct GetIamPolicyRequest: {{err}}", err)
	}
	if err := verifyConstructRequest(req, rType); err != nil {
		return err
	}

	req, err = resource.SetIamPolicyRequest(nil)
	if err != nil {
		return errwrap.Wrapf("unable to construct SetIamPolicyRequest: {{err}}", err)
	}
	if err := verifyConstructRequest(req, rType); err != nil {
		return err
	}
	return nil
}

func verifyConstructRequest(req *http.Request, resourceType string) error {
	collectionIds := strings.Split(resourceType, "/")
	for idx := range collectionIds {
		rid := fmt.Sprintf("/aFakeId%d", idx)
		if !strings.Contains(req.URL.Path, rid) {
			return fmt.Errorf("expected expanded request URL %s to contain %s", req.URL.String(), rid)
		}
	}
	return nil
}
