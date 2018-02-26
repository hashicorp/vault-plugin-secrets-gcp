package util

import (
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"os"
)

const googleCredentialsEnv = "TEST_GOOGLE_CREDENTIALS"
const googleProjectEnv = "TEST_GOOGLE_PROJECT"

func GetTestCredentials() (*gcputil.GcpCredentials, error) {
	credentialsJSON := os.Getenv(googleCredentialsEnv)
	if credentialsJSON == "" {
		return nil, fmt.Errorf("%s must be set to JSON string of valid Google credentials file", googleCredentialsEnv)
	}

	credentials, err := gcputil.Credentials(credentialsJSON)
	if err != nil {
		return nil, fmt.Errorf("valid Google credentials JSON could not be read from %s env variable: %v", googleCredentialsEnv, err)
	}
	return credentials, nil
}

func GetTestProject() (string, error) {
	project := os.Getenv(googleProjectEnv)
	if project == "" {
		return "", fmt.Errorf("%s must be set to JSON string of valid Google credentials file", googleProjectEnv)
	}
	return project, nil
}
