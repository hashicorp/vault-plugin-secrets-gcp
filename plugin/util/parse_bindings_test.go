// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"encoding/base64"
	"testing"
)

type testCase struct {
	Input    string
	Expected map[string][]string
}

var testCases = []testCase{
	{
		Input: `
			resource "projects/X" {
				roles = [
					"roles/viewer",
				],
			}`,
		Expected: map[string][]string{
			"projects/X": {
				"roles/viewer",
			},
		},
	},

	{
		Input: `
			resource "projects/X" {
				roles = [
					"roles/role1",
					"projects/X/roles/customRole",
				],
			}
			resource "//cloudresourcemanagers.com/projects/Y" {
				roles = [
					"roles/compute.admin",
					"roles/anotherRole",
				],
			}`,
		Expected: map[string][]string{
			"projects/X": {
				"roles/role1",
				"projects/X/roles/customRole",
			},
			"//cloudresourcemanagers.com/projects/Y": {
				"roles/compute.admin",
				"roles/anotherRole",
			},
		},
	},
}

func TestParseBindings(t *testing.T) {
	checkParseBindings(t, false)
}

func TestParseBindingsB64(t *testing.T) {
	checkParseBindings(t, true)
}

func checkParseBindings(t *testing.T, encodeB64 bool) {
	for _, tc := range testCases {
		input := tc.Input
		if encodeB64 {
			input = base64.StdEncoding.EncodeToString([]byte(tc.Input))
		}

		binds, err := ParseBindings(input)
		if err != nil {
			t.Errorf("unexpected error: %v \nInput: \n%s\n", err, tc.Input)
		}
		if len(tc.Expected) != len(binds) {
			t.Errorf("unexpected difference in number of bindings parsed; expected %d, got %d", len(tc.Expected), len(binds))
		}
		for res, expected := range tc.Expected {
			actual, ok := binds[res]
			if !ok {
				t.Errorf("expected binding for resource '%s' not found", res)
				continue
			}

			if !actual.Equals(ToSet(expected)) {
				t.Errorf("expected bindings for resource '%s': %v; actual: %v", res, expected, actual.ToSlice())
			}
		}
	}
}
