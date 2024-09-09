// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"google.golang.org/api/discovery/v1"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
)

const (
	templateFile = "resource_config_template"
	outputFile   = "resources_generated.go"
)

// allowedPolicyRefs lists all the possible $ref values
// that the policy key may take in the different Google APIs
var allowedPolicyRefs = map[string]bool{
	"Policy":              true,
	"GoogleIamV1Policy":   true,
	"ApigatewayPolicy":    true,
	"IamPolicy":           true,
	"GoogleIamV1__Policy": true,
}

var sanizitedCollectionIds = map[string]string{
	// Storage doesn't use properly RESTful resource path in request.
	"b": "buckets",
	"o": "objects",
}

var sanizitedTypeKeys = map[string]string{
	// Storage doesn't use properly RESTful resource path in request.
	"b":   "buckets",
	"b/o": "buckets/objects",
}

var correctedRequestFormats = map[string]string{
	// Compute Discovery Doc request format is incorrect.
	"compute": `{"policy": %s}`,
}

func main() {
	if err := generateConfig(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func checkResource(name string, fullPath string, resource *discovery.RestResource, doc *discovery.RestDescription, docMeta *discovery.DirectoryListItems, config iamutil.GeneratedResources) error {
	for rName, child := range resource.Resources {
		err := checkResource(rName, fullPath+"/"+rName, &child, doc, docMeta, config)
		if err != nil {
			return err
		}
	}

	getM, hasGet := resource.Methods["getIamPolicy"]
	setM, hasSet := resource.Methods["setIamPolicy"]

	if !hasGet || !hasSet {
		// Can't manage anything without both setIamPolicy and getIamPolicy
		return nil
	}

	getK := strings.Join(getM.ParameterOrder, "/")
	typeKey, replacementMap, err := parseTypeKey(doc.RootUrl+doc.ServicePath, &getM)
	if err != nil {
		return err
	}

	// if an override is available for this resource, no need to check
	if _, ok := resourceOverrides[typeKey]; ok {
		return nil
	}

	setK := strings.Join(setM.ParameterOrder, "/")

	if getK != setK {
		return fmt.Errorf("unexpected method formats, get parameters: %s, set parameters: %s", getK, setK)
	}

	var requestTmpl string
	if tmpl, ok := correctedRequestFormats[doc.Name]; ok {
		requestTmpl = tmpl
	} else {
		sch, ok := doc.Schemas[setM.Request.Ref]
		if !ok {
			return fmt.Errorf("could not find setIamPolicy request ref schema %s", setM.Request.Ref)
		}
		requestTmpl = getPolicyReplacementString(&sch)
	}
	if requestTmpl == "" {
		return fmt.Errorf("unable to get schema for setIamPolicy request, could not find policy in schema '%s'", setM.Request.Ref)
	}

	r := iamutil.RestResource{
		Name:               name,
		TypeKey:            typeKey,
		Service:            doc.Name,
		IsPreferredVersion: docMeta.Preferred,
		GetMethod: iamutil.RestMethod{
			HttpMethod: getM.HttpMethod,
			BaseURL:    doc.RootUrl + doc.ServicePath,
			Path:       getM.Path,
		},
		SetMethod: iamutil.RestMethod{
			HttpMethod:    setM.HttpMethod,
			BaseURL:       doc.RootUrl + doc.ServicePath,
			Path:          setM.Path,
			RequestFormat: requestTmpl,
		},
		Parameters:                getM.ParameterOrder,
		CollectionReplacementKeys: replacementMap,
	}

	addToConfig(typeKey, doc.Name, doc.Version, r, config)
	if saneKey, ok := sanizitedTypeKeys[typeKey]; ok {
		r.TypeKey = saneKey
		addToConfig(saneKey, doc.Name, doc.Version, r, config)
	}

	return nil
}

func parseTypeKey(rootUrl string, mtd *discovery.RestMethod) (string, map[string]string, error) {
	if strings.Contains(mtd.Path, "{+resource}") {
		return parseTypeKeyFromPattern(mtd.Parameters["resource"].Pattern), nil, nil
	}

	// Parse type key from path:
	fullUrl := rootUrl + mtd.Path
	u, err := url.Parse(fullUrl)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse URL from '%s'", fullUrl)
	}
	pathTkns := strings.Split(strings.Trim(u.Path, "/"), "/")
	pathIdx := 0
	typeKey := ""

	replacementMap := make(map[string]string)
	for _, paramName := range mtd.ParameterOrder {
		expectedTkn := fmt.Sprintf("{%s}", paramName)
		for pathIdx < len(pathTkns) {
			if strings.HasPrefix(pathTkns[pathIdx], expectedTkn) {
				break
			}
			pathIdx++
		}

		if pathIdx <= 0 || pathIdx >= len(pathTkns) {
			return "", nil, fmt.Errorf("path '%s' has {%s} at out-of-bounds index %d", mtd.Path, paramName, pathIdx)
		}
		typeKey += fmt.Sprintf("/%s", pathTkns[pathIdx-1])
		replacementMap[pathTkns[pathIdx-1]] = paramName
		saneColId, ok := sanizitedCollectionIds[pathTkns[pathIdx-1]]
		if ok {
			replacementMap[saneColId] = paramName
		}
	}
	return strings.Trim(typeKey, "/"), replacementMap, nil
}

func parseTypeKeyFromPattern(pattern string) string {
	typeKey := ""
	re := regexp.MustCompile("^[a-zA-Z]*[a-z]$")
	ptn := strings.Trim(pattern, "^$/")
	// In a few resources, the Discovery API hardcodes "global" which if set
	// as the TypeKey breaks the common pattern in tests.
	ptn = strings.ReplaceAll(ptn, "global/", "")
	tkns := strings.Split(ptn, "/")
	for _, tkn := range tkns {
		if re.MatchString(tkn) {
			typeKey += tkn + "/"
		}
	}
	return strings.TrimRight(typeKey, "/")
}

func getPolicyReplacementString(sch *discovery.JsonSchema) string {
	if sch.Id == "Policy" || allowedPolicyRefs[sch.Ref] {
		return "%s"
	}

	for propK, child := range sch.Properties {
		fmtStr := getPolicyReplacementString(&child)
		if fmtStr != "" {
			return fmt.Sprintf(`{"%s": %s}`, propK, fmtStr)
		}
	}

	return ""
}

func addToConfig(resourceKey, service, version string, r iamutil.RestResource, config iamutil.GeneratedResources) {
	log.Printf("adding [%s %s %s]", resourceKey, service, version)
	if _, ok := config[resourceKey]; !ok {
		config[resourceKey] = make(map[string]map[string]iamutil.RestResource)
	}
	if _, ok := config[resourceKey][service]; !ok {
		config[resourceKey][service] = make(map[string]iamutil.RestResource)
	}
	config[resourceKey][service][version] = r
}

func generateConfig() error {
	docs, err := getURL[discovery.DirectoryList]("https://www.googleapis.com/discovery/v1/apis")
	if err != nil {
		return err
	}
	if docs == nil {
		return errors.New("no API docs found")
	}

	config := make(iamutil.GeneratedResources)

	var mErr error
	for _, docMeta := range docs.Items {
		if versions, ok := resourceSkips[docMeta.Name]; ok {
			if _, ok := versions[docMeta.Version]; ok {
				log.Printf("skipping %q (version %q)", docMeta.Name, docMeta.Version)
				continue
			}
		}
		doc, docErr := getURL[discovery.RestDescription](docMeta.DiscoveryRestUrl)
		if docErr != nil || doc == nil {
			// Endpoints that are dynamically added by Google can be unpredictable
			// and at times will return unexpected status code errors.
			// We do not want to break the plugin build for this, we can
			// skip adding these resources to the config until they are resolved by GCP
			log.Printf("skipping %q (version %q), could not find doc - %s", docMeta.Name, docMeta.Version, docErr)
			continue
		}

		for rName, resource := range doc.Resources {
			if resErr := checkResource(rName, rName, &resource, doc, docMeta, config); resErr != nil {
				mErr = errors.Join(mErr, fmt.Errorf("unable to add %q (version %q): %w", docMeta.Name, docMeta.Version, resErr))
			}
		}
	}

	// Inject overrides that use ACLs instead of IAM policies
	for k, v := range resourceOverrides {
		config[k] = v
	}

	if err := writeConfig(config); err != nil {
		return err
	}

	if mErr != nil {
		return fmt.Errorf("errors while generating config: \n%s", mErr)
	}
	return nil
}

func getURL[T any](url string) (*T, error) {
	var t T
	listResp, err := http.Get(url)
	if err != nil {
		return &t, err
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		return &t, fmt.Errorf("unexpected status code %d from GET %s", listResp.StatusCode, url)
	}
	listBody, err := io.ReadAll(listResp.Body)
	if err != nil {
		return &t, err
	}
	if err := json.Unmarshal(listBody, &t); err != nil {
		return &t, err
	}

	return &t, nil
}

func writeConfig(config iamutil.GeneratedResources) error {
	tpl, err := template.ParseFiles(filepath.Join("internal", templateFile))
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "main", config); err != nil {
		return err
	}

	srcBytes, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("[ERROR] Outputting unformatted src:\n %s\n", buf.String())
		return fmt.Errorf("error formatting generated code: %w", err)
	}

	dst, err := os.Create(outputFile)
	defer dst.Close()
	if err != nil {
		return err
	}

	dst.Write(srcBytes)
	return nil
}
