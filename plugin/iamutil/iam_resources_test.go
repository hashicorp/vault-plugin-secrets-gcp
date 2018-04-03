package iamutil

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/errwrap"
)

func TestEnabledIamResources_RelativeName(t *testing.T) {
	enabledApis := GetEnabledIamResources()

	for resourceType, services := range generatedResources {
		testRelName := getFakeId(resourceType)

		var needsService = len(services) > 1
		var needsVersion bool
		if !needsService {
			for _, versions := range services {
				needsVersion = expectVersionError(versions)
				break
			}
		}

		resource, err := enabledApis.Resource(testRelName)
		if !needsService && !needsVersion {
			if err != nil {
				t.Errorf("failed to get resource for relative resource name %s (type: %s): %v", testRelName, resourceType, err)
			}
			if err = verifyResource(resourceType, resource.(*iamResourceImpl)); err != nil {
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

	for resourceType, services := range generatedResources {
		for service, versions := range services {
			testFullName := fmt.Sprintf("//%s.googleapis.com/%s", service, getFakeId(resourceType))
			resource, err := enabledApis.Resource(testFullName)

			if !expectVersionError(versions) {
				if err != nil {
					t.Errorf("failed to get resource for full resource name %s (type: %s): %v", testFullName, resourceType, err)
				}
				if err = verifyResource(resourceType, resource.(*iamResourceImpl)); err != nil {
					t.Errorf("could not verify resource for relative resource name %s: %v", testFullName, err)
				}
			} else if resource != nil || err == nil {
				t.Errorf("expected error for using full resource name %s (type: %s), got resource:\n %v\n", testFullName, resourceType, resource)
				continue
			}
		}
	}
}

func expectVersionError(versions map[string]*IamResourceConfig) bool {
	needsVersion := len(versions) > 1
	for _, cfg := range versions {
		needsVersion = needsVersion && !cfg.Service.IsPreferredVersion
	}
	return needsVersion
}

func TestEnabledIamResources_SelfLink(t *testing.T) {
	enabledApis := GetEnabledIamResources()

	for resourceType, services := range generatedResources {
		for _, versions := range services {
			for _, cfg := range versions {
				relName := getFakeId(resourceType)
				testSelfLink := fmt.Sprintf("%s/%s/%s", cfg.Service.RootUrl, cfg.Service.Version, relName)
				isProjectLevel := strings.HasPrefix(relName, "projects/")
				if isProjectLevel && strings.HasSuffix(cfg.Service.ServicePath, "projects/") {
					testSelfLink = cfg.Service.RootUrl + cfg.Service.ServicePath + strings.TrimPrefix(relName, "projects/")
				}

				resource, err := enabledApis.Resource(testSelfLink)
				if isProjectLevel {
					if err != nil {
						t.Errorf("failed to get resource for self link %s (type: %s): %v", testSelfLink, resourceType, err)
					}
					if err = verifyResource(resourceType, resource.(*iamResourceImpl)); err != nil {
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

func verifyHttpMethod(typeKey string, m *HttpMethodCfg) error {
	if len(m.Path) == 0 {
		return fmt.Errorf("empty http method path")
	}

	tokens := strings.Split(typeKey, "/")
	for _, cid := range tokens {
		k, ok := m.ReplacementKeys[cid]
		if !ok {
			return fmt.Errorf("expected replacement keys to contain collection id %s", cid)
		}
		if !strings.Contains(m.Path, fmt.Sprintf("{%s}", k)) {
			return fmt.Errorf("expected path '%s' to contain replacement key '%s' for collection id '%s'", m.Path, k, cid)
		}
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
	for typeKey, services := range generatedResources {
		for service, versions := range services {
			for ver, cfg := range versions {
				serviceCfg := cfg.Service
				if serviceCfg == nil {
					t.Errorf("nil service config for resources[%s][%s][%s]", service, ver, typeKey)
				}

				if serviceCfg.Name != service {
					t.Errorf("mismatch service config name '%s' for resources[%s][%s][%s]", serviceCfg.Name, service, ver, typeKey)
				}

				if serviceCfg.Version != ver {
					t.Errorf("mismatch service config version '%s' for resources[%s][%s][%s]", serviceCfg.Version, service, ver, typeKey)
				}

				if serviceCfg.RootUrl == "" && serviceCfg.ServicePath == "" {
					t.Errorf("empty base url for service config resource[%s][%s][%s]", service, ver, typeKey)
				}

				if err := verifyHttpMethod(typeKey, cfg.GetIamPolicy); err != nil {
					t.Errorf("error with resource[%s][%s][%s].GetIamPolicy: %v", service, ver, typeKey, err)
				}
				if err := verifyHttpMethod(typeKey, cfg.SetIamPolicy); err != nil {
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

func verifyResource(rType string, resource *iamResourceImpl) error {
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
