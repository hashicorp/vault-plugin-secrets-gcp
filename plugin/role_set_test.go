package gcpsecrets

import (
	"fmt"
	"testing"
)

func Test_roleSetServiceAccountDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "display name less than max size",
			input: "display-name-that-is-not-truncated",
			want:  fmt.Sprintf(serviceAccountDisplayNameTmpl, "display-name-that-is-not-truncated"),
		},
		{
			name:  "display name greater than max size",
			input: "display-name-that-is-really-long-vault-plugin-secrets-gcp-role-name",
			want:  fmt.Sprintf(serviceAccountDisplayNameTmpl, "display-name-that-is-really-long-vault-pl43b18db3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roleSetServiceAccountDisplayName(tt.input)
			checkDisplayNameLength(t, got)
			if got != tt.want {
				t.Errorf("roleSetServiceAccountDisplayName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func checkDisplayNameLength(t *testing.T, displayName string) {
	if len(displayName) > serviceAccountDisplayNameMaxLen {
		t.Errorf("expected display name to be less than or equal to %v. actual name '%v'", serviceAccountDisplayNameMaxLen, displayName)
	}
}
