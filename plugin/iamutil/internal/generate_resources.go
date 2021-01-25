package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/format"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"google.golang.org/api/discovery/v1"
)

const (
	templateFile = "resource_config_template"
	outputFile   = "resources_generated.go"
)

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
		checkResource(rName, fullPath+"/"+rName, &child, doc, docMeta, config)
	}

	getM, hasGet := resource.Methods["getIamPolicy"]
	setM, hasSet := resource.Methods["setIamPolicy"]

	if !hasGet && !hasSet {
		return nil
	}

	getK := strings.Join(getM.ParameterOrder, "/")
	setK := strings.Join(setM.ParameterOrder, "/")

	if getK != setK {
		return fmt.Errorf("unexpected method formats, get parameters: %s, set parameters: %s", getK, setK)
	}

	typeKey, replacementMap, err := parseTypeKey(doc.RootUrl+doc.ServicePath, &getM)
	if err != nil {
		return err
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
	if sch.Id == "Policy" || sch.Ref == "Policy" {
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
	docsClient, err := discovery.New(cleanhttp.DefaultClient())
	if err != nil {
		return err
	}

	docs, err := docsClient.Apis.List().Do()
	if err != nil {
		return err
	}
	if docs == nil {
		return errors.New("no API docs found")
	}

	config := make(iamutil.GeneratedResources)

	for _, docMeta := range docs.Items {
		doc, err := docsClient.Apis.GetRest(docMeta.Name, docMeta.Version).Fields(
			"name",
			"resources",
			"rootUrl",
			"schemas",
			"servicePath",
			"version",
		).Do()
		if err != nil || doc == nil {
			err = multierror.Append(err,
				errwrap.Wrapf(
					fmt.Sprintf("[WARNING] Unable to add '%s' (version '%s'), could not find doc - {{err}}", docMeta.Name, docMeta.Version), err))
			continue
		}

		for rName, resource := range doc.Resources {
			if err := checkResource(rName, rName, &resource, doc, docMeta, config); err != nil {
				err = multierror.Append(err,
					errwrap.Wrapf(
						fmt.Sprintf("[WARNING] Unable to add '%s' (version '%s'): {{err}}", docMeta.Name, docMeta.Version), err))
			}
		}
	}
	if err != nil {
		return err
	}

	// Inject overrides that use ACLs instead of IAM policies
	for k, v := range resourceOverrides {
		config[k] = v
	}

	if err := writeConfig(config); err != nil {
		return err
	}

	return nil
}

func writeConfig(config iamutil.GeneratedResources) error {

	tpl, err := template.ParseFiles(fmt.Sprintf("internal/%s", templateFile))
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "main", config); err != nil {
		return err
	}

	srcBytes, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("[ERROR] Outputting unformatted src:\n %s\n", string(buf.Bytes()))
		return errwrap.Wrapf("error formatting generated code: {{err}}", err)
	}

	dst, err := os.Create(outputFile)
	defer dst.Close()
	if err != nil {
		return err
	}

	dst.Write(srcBytes)
	return nil
}
