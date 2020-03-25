package iamutil

import (
	"context"
	"github.com/hashicorp/go-gcp-common/gcputil"
)

// IamResource handles constructing HTTP requests for getting and
// setting IAM policies.
type Resource interface {
	GetIamPolicy(context.Context, *ApiHandle) (*Policy, error)
	SetIamPolicy(context.Context, *ApiHandle, *Policy) (*Policy, error)
	GetConfig() *RestResource
	GetRelativeId() *gcputil.RelativeResourceName
}

type RestResource struct {
	// Name is the base name of the resource
	// i.e. for a GCE instance: "instance"
	Name string

	// Type Key is the identifying path for the resource, or
	// the RESTful resource identifier without resource IDs
	// i.e. For a GCE instance: "projects/zones/instances"
	TypeKey string

	// Service Information
	// Service is the name of the service this resource belongs to.
	Service string

	// IsPreferredVersion is true if this version of the API/resource is preferred.
	IsPreferredVersion bool

	// IsPreferredVersion is true if this version of the API/resource is preferred.
	GetMethod RestMethod

	// IsPreferredVersion is true if this version of the API/resource is preferred.
	SetMethod RestMethod

	// Ordered parameters to be replaced in method paths
	Parameters []string

	// collection Id --> parameter to be replaced {} name
	CollectionReplacementKeys map[string]string
}

type RestMethod struct {
	HttpMethod    string
	BaseURL       string
	Path          string
	RequestFormat string
}
