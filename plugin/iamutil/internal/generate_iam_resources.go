package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"go/format"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
)

const (
	standardColIdFormat = "^[a-z][a-zA-Z]*s$"
	templateFile        = "gen_iam_template"
	outputFile          = "iam_resources_generated.go"
	discoveryBaseUrl    = "https://www.googleapis.com/discovery/v1/apis"
)

var requiredIamMethods = []string{
	"getIamPolicy",
	"setIamPolicy",
}
var colIdRe = regexp.MustCompile(standardColIdFormat)

// Map of possible generated resource types that should have more canonical resource type
// i.e. storage is the worst
var specialCases = map[string]altResource{
	"b": {
		TypeKey: "buckets",
		SwapKeys: map[string]string{
			"b": "buckets",
		},
	},
	"b/o": {
		TypeKey: "buckets/objects",
		SwapKeys: map[string]string{
			"b": "buckets",
			"o": "objects",
		},
	},
}

type altResource struct {
	TypeKey  string
	SwapKeys map[string]string
}

func main() {
	if err := genResources(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

type discoveryDocMeta struct {
	URL       string `json:"discoveryRestUrl"`
	Preferred bool   `json:"preferred"`
}

type resourceMap map[string]map[string]map[string]*iamutil.IamResourceConfig
type serviceMap map[string]map[string]*iamutil.ServiceConfig

func genResources() error {
	data := &struct {
		Docs []*discoveryDocMeta `json:"items"`
	}{}
	if err := readDiscoveryDocMetadata(data); err != nil {
		return err
	}

	resources := make(resourceMap)
	services := make(serviceMap)

	for _, dMeta := range data.Docs {
		doc, err := readDiscoveryDoc(dMeta.URL)
		if err != nil {
			return err
		}
		doc.isPreferred = dMeta.Preferred
		addIfIamEnabled(resources, services, doc)
	}

	log.Printf(`[DEBUG] Writing generated code to file "%s"`, outputFile)

	if err := writeToFile(resources, services); err != nil {
		return err
	}

	return nil
}

func addIfIamEnabled(resources resourceMap, services serviceMap, doc *discoveryDoc) {
	service := &iamutil.ServiceConfig{
		Name:               doc.Name,
		Version:            doc.Version,
		IsPreferredVersion: doc.isPreferred,
		RootUrl:            doc.RootUrl,
		ServicePath:        doc.ServicePath,
	}

	for rName, r := range doc.Resources {
		r.addIfIamSupported(resources, services, rName, service)
	}
}

// Discovery API service helpers
func readDiscoveryDocMetadata(out interface{}) error {
	resp, err := http.Get(discoveryBaseUrl + "?fields=items(discoveryRestUrl,preferred)")
	if err != nil {
		return fmt.Errorf("unable to make request to discovery service at '%s': '%v'", discoveryBaseUrl, err)
	}
	if resp == nil {
		return errors.New("got empty response from discovery API, try again")
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	return nil
}

func readDiscoveryDoc(docUrl string) (*discoveryDoc, error) {
	resp, err := http.Get(docUrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	doc := &discoveryDoc{}
	if err = json.Unmarshal(respBytes, doc); err != nil {
		return nil, err
	}

	return doc, nil
}

type discoveryDoc struct {
	Name    string `json:"name"`
	Version string `json:"version"`

	RootUrl     string `json:"rootUrl"`
	ServicePath string `json:"servicePath"`

	Resources map[string]*docResource `json:"resources"`

	// Not part of actual discovery doc
	isPreferred bool
}

type docResource struct {
	Children map[string]*docResource `json:"resources"`
	Methods  map[string]*docMethod   `json:"methods"`
}

func (r *docResource) addIfIamSupported(resources resourceMap, services serviceMap, resourceName string, service *iamutil.ServiceConfig) {
	for cName, child := range r.Children {
		child.addIfIamSupported(resources, services, cName, service)
	}

	if r.supportsIam() {
		typeKey, setMethod := r.Methods["setIamPolicy"].parseMethod(service)
		typeKeyGet, getMethod := r.Methods["getIamPolicy"].parseMethod(service)

		if typeKey != typeKeyGet {
			log.Printf("[WARNING] skipping '%s' '%s' '%s': has different resource path format for set/getIamPolicy \n", service.Name, service.Version, resourceName)
			return
		}
		if setMethod == nil {
			log.Printf("[WARNING] skipping '%s' '%s' '%s': invalid setMethod %v", service.Name, service.Version, resourceName, r.Methods["setIamPolicy"])
			return
		}
		if getMethod == nil {
			log.Printf("[WARNING] skipping '%s' '%s' '%s': invalid getMethod %v", service.Name, service.Version, resourceName, r.Methods["getIamPolicy"])
			return
		}
		if _, ok := specialCases[typeKey]; !ok {
			colIds := strings.Split(typeKey, "/")
			standard := true
			for _, cid := range colIds {
				if standard = isStandardFormat(cid); !standard {
					break
				}
			}
			if !standard {
				log.Printf("[WARNING] '%s' '%s' '%s': Generated resource type '%s' from path does not look standard - consider adding a specialCase", service.Name, service.Version, resourceName, typeKey)
			}
		}

		if _, ok := services[service.Name]; !ok {
			services[service.Name] = make(map[string]*iamutil.ServiceConfig)
		}
		services[service.Name][service.Version] = service

		resources.addToMap(
			typeKey, service.Name, service.Version,
			&iamutil.IamResourceConfig{
				SetIamPolicy: setMethod,
				GetIamPolicy: getMethod,
			})

		if alt, ok := specialCases[typeKey]; ok {

			resources.addToMap(
				alt.TypeKey, service.Name, service.Version,
				&iamutil.IamResourceConfig{
					SetIamPolicy: copyWithSwappedKeys(setMethod, alt.SwapKeys),
					GetIamPolicy: copyWithSwappedKeys(getMethod, alt.SwapKeys),
				})
		}
	}
}

func (m resourceMap) addToMap(typeKey, serviceName, serviceVer string, cfg *iamutil.IamResourceConfig) {
	if _, ok := m[typeKey]; !ok {
		m[typeKey] = make(map[string]map[string]*iamutil.IamResourceConfig)
	}
	if _, ok := m[typeKey][serviceName]; !ok {
		m[typeKey][serviceName] = make(map[string]*iamutil.IamResourceConfig)
	}
	m[typeKey][serviceName][serviceVer] = cfg
}

func isStandardFormat(cid string) bool {
	return len(colIdRe.FindString(cid)) > 0
}

func (r *docResource) supportsIam() bool {
	for _, methodName := range requiredIamMethods {
		_, ok := r.Methods[methodName]
		if !ok {
			return false
		}
	}
	return true
}

type docMethod struct {
	HttpMethod string `json:"httpMethod"`
	FlatPath   string `json:"flatPath"`
	Path       string `json:"path"`
}

func (m *docMethod) parseMethod(service *iamutil.ServiceConfig) (string, *iamutil.HttpMethodCfg) {
	path := m.FlatPath
	if len(path) == 0 {
		path = m.Path
	}

	if len(path) == 0 {
		return "", nil
	}

	rPath := getResourcePath(path, service)
	relName, err := gcputil.ParseRelativeName(rPath)
	if err != nil {
		return "", nil
	}

	for k, v := range relName.IdTuples {
		relName.IdTuples[k] = strings.Trim(v, "{}")
	}

	return relName.TypeKey, &iamutil.HttpMethodCfg{
		HttpMethod:      m.HttpMethod,
		Path:            path,
		ReplacementKeys: relName.IdTuples,
	}
}

func getResourcePath(methodPath string, service *iamutil.ServiceConfig) string {
	i := strings.LastIndex(methodPath, "}")
	if i < 0 {
		return methodPath
	}
	resourcePath := methodPath[:i+1]

	// Deal with special cases:
	// Compute APIs
	if strings.HasSuffix(service.ServicePath, "/projects/") {
		resourcePath = "projects/" + resourcePath
	}

	// APIs that attach version to method path
	verPrefix := fmt.Sprintf("%s/", service.Version)
	if strings.HasPrefix(methodPath, verPrefix) {
		resourcePath = strings.TrimPrefix(resourcePath, verPrefix)
	}

	return strings.Trim(resourcePath, "/")
}

// writeToFile outputs generated config to a Go file.
func writeToFile(resources resourceMap, services serviceMap) error {
	tpl, err := template.ParseFiles(fmt.Sprintf("internal/%s", templateFile))
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	data := &struct {
		Resources resourceMap
		Services  serviceMap
	}{
		Resources: resources,
		Services:  services,
	}
	if err := tpl.ExecuteTemplate(&buf, "main", data); err != nil {
		return err
	}

	srcBytes, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("[ERROR] Outputting unformatted src:\n %s\n", string(buf.Bytes()))
		return fmt.Errorf("error formatting generated code: %v", err)
	}

	dst, err := os.Create(outputFile)
	defer dst.Close()
	if err != nil {
		return err
	}

	dst.Write(srcBytes)
	return nil
}

func copyWithSwappedKeys(mtd *iamutil.HttpMethodCfg, swapKeys map[string]string) *iamutil.HttpMethodCfg {
	cpy := &iamutil.HttpMethodCfg{}
	*cpy = *mtd
	cpy.ReplacementKeys = make(map[string]string)
	for k, v := range mtd.ReplacementKeys {
		newK, ok := swapKeys[k]
		if ok {
			cpy.ReplacementKeys[newK] = v
		} else {
			cpy.ReplacementKeys[k] = v
		}
	}
	return cpy
}
