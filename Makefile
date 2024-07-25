TOOL?=vault-gcp-secrets-plugin
TEST?=$$(go list ./... | grep -v /vendor/)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr
EXTERNAL_TOOLS=
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)

PLUGIN_NAME?=$(shell command ls bin/)
PLUGIN_DIR?=$$GOPATH/vault-plugins
PLUGIN_PATH?=local-gcp

# bin generates the releasable binaries for this plugin
.PHONY: bin
bin: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: default
default: dev

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin, except for quickdev which
# is only put into /bin/
.PHONY: quickdev
quickdev: generate
	@CGO_ENABLED=0 go build -tags='$(BUILD_TAGS)' -o bin/vault-plugin-secrets-gcp cmd/vault-plugin-secrets-gcp/main.go
.PHONY: dev
dev: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
.PHONY: dev-dynamic
dev-dynamic: generate
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: testcompile
testcompile: fmtcheck generate
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

.PHONY: test
test:
	@go test -short ./... $(TESTARGS)

.PHONY: testacc
testacc:
	@go test ./... $(TESTARGS)

# generate runs `go generate` to build the dynamically generated
# source files.
.PHONY: generate
generate:
	@go generate $(shell go list ./plugin/... | grep -v /vendor/)

# bootstrap the build by downloading additional tools
.PHONY: bootstrap
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofmt -w $(GOFMT_FILES) && cd bootstrap/terraform && terraform fmt

.PHONY: update-resources
update-resources:
	go run ./plugin/iamutil/internal

.PHONY: setup-env
setup-env:
	cd bootstrap/terraform && terraform init && terraform apply -auto-approve

.PHONY: teardown-env
teardown-env:
	cd bootstrap/terraform && terraform init && terraform destroy -auto-approve

.PHONY: configure
configure: dev
	@./bootstrap/configure.sh \
	$(PLUGIN_DIR) \
	$(PLUGIN_NAME) \
	$(PLUGIN_PATH) \
	$(GOOGLE_TEST_CREDENTIALS)
