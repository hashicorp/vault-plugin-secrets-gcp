// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func Test_RoleSetServiceAccountDisplayName(t *testing.T) {
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

func TestRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	t.Parallel()
	t.Run("First try success", func(t *testing.T) {
		_, err := retryWithExponentialBackoff(context.Background(), func() (interface{}, bool, error) {
			return nil, true, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})

	t.Run("Three retries", func(t *testing.T) {
		t.Parallel()
		count := 0

		_, err := retryWithExponentialBackoff(context.Background(), func() (interface{}, bool, error) {
			count++
			if count >= 3 {
				return nil, true, nil
			}
			return nil, false, nil
		})
		if count != 3 {
			t.Fatalf("unexpected count: %d", count)
		}

		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})

	t.Run("Error on attempt", func(t *testing.T) {
		t.Parallel()
		_, err := retryWithExponentialBackoff(context.Background(), func() (interface{}, bool, error) {
			return nil, true, errors.New("Fail")
		})
		if err == nil || !strings.Contains(err.Error(), "Fail") {
			t.Fatalf("expected failure error, got: %v", err)
		}
	})

	// timeout test
	t.Run("Timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode.")
		}
		t.Parallel()
		start := time.Now()

		timeout := 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		called := 0
		_, err := retryWithExponentialBackoff(ctx, func() (interface{}, bool, error) {
			called++
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if called == 0 {
			t.Fatalf("retryable function was never called")
		}
		assertDuration(t, elapsed, timeout, 250*time.Millisecond)
	})

	t.Run("Cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(1 * time.Second)
			cancel()
		}()

		start := time.Now()
		_, err := retryWithExponentialBackoff(ctx, func() (interface{}, bool, error) {
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		assertDuration(t, elapsed, 1*time.Second, 250*time.Millisecond)

		if err == nil {
			t.Fatalf("expected err: got nil")
		}
		underlyingErr := errors.Unwrap(err)
		if underlyingErr != context.Canceled {
			t.Fatalf("expected %s, got: %v", context.Canceled, err)
		}
	})
}

func checkDisplayNameLength(t *testing.T, displayName string) {
	if len(displayName) > serviceAccountDisplayNameMaxLen {
		t.Errorf("expected display name to be less than or equal to %v. actual name '%v'", serviceAccountDisplayNameMaxLen, displayName)
	}
}

// assertDuration with a certain amount of flex in the exact value
func assertDuration(t *testing.T, actual, expected, delta time.Duration) {
	t.Helper()

	diff := actual - expected
	if diff < 0 {
		diff = -diff
	}

	if diff > delta {
		t.Fatalf("Actual duration %s does not equal expected %s with delta %s", actual, expected, delta)
	}
}
