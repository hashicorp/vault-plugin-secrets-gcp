# Copyright IBM Corp. 2018, 2025
# SPDX-License-Identifier: MPL-2.0

resource "//cloudresourcemanager.googleapis.com/projects/vault-gcp-regression-test" {
    roles = ["roles/viewer"]
}
