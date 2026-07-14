SHELL := /bin/bash

.PHONY: run test race vet build check dependency-check module-boundary-check ui-check browser-e2e kernel-integration nodeagent-generate nodeagent-check-generated profile-check helm-check helm-manifest helm-manifest-check

GO ?= go
HZN ?= $(GO) run m31labs.dev/horizon/cmd/hzn
TEST_DIGEST := sha256:1111111111111111111111111111111111111111111111111111111111111111
HELM_TEST_ARGS := --set image.digest=$(TEST_DIGEST) --set nodeAgent.image.digest=$(TEST_DIGEST) --set sandbox.agentImage=example.invalid/agent@$(TEST_DIGEST) --set sandbox.attachImage=example.invalid/mercutio@$(TEST_DIGEST) --set sandbox.graftImage=example.invalid/graft@$(TEST_DIGEST) --set sandbox.armgateImage=example.invalid/mercutio@$(TEST_DIGEST) --set operator.email=operator@example.invalid

run:
	$(GO) run ./cmd/mercutio

test:
	$(GO) test ./...
	cd nodeagent && $(GO) test ./...

race:
	$(GO) test -race ./internal/cell ./internal/transport ./internal/capability ./internal/evidence ./internal/shadow
	cd nodeagent && $(GO) test -race ./internal/agent

dependency-check:
	@versions=$$($(GO) list -m -f '{{if or (eq .Path "m31labs.dev/gosx") (eq .Path "m31labs.dev/gosx/editor") (eq .Path "github.com/odvcencio/gotreesitter")}}{{.Path}} {{.Version}}{{end}}' all); \
	test "$$(printf '%s\n' "$$versions" | sed '/^$$/d' | wc -l)" -eq 3; \
	! printf '%s\n' "$$versions" | grep -Eq -- '-[0-9]{14}-[0-9a-f]{12}$$'
	@cd nodeagent && version=$$($(GO) list -m -f '{{if eq .Path "github.com/odvcencio/gotreesitter"}}{{.Version}}{{end}}' all); test "$$version" = "v0.35.0"

module-boundary-check:
	@bad=$$(cd nodeagent && $(GO) list -deps ./... | grep -E '^(m31labs.dev/gosx($$|/)|k8s.io/)' || true); \
	test -z "$$bad" || { echo "forbidden Node Agent dependencies:" >&2; echo "$$bad" >&2; exit 1; }
	@! grep -R --include='*.go' -E 'm31labs.dev/mercutio/(internal|cmd)' nodeagent

ui-check:
	@test -z "$$(find . -path './.git' -prune -o -name '*.js' -print)"

browser-e2e: build
	./scripts/browser-e2e.sh

kernel-integration:
	./scripts/kernel-integration.sh

vet:
	$(GO) vet ./...
	cd nodeagent && $(GO) vet ./...

build:
	$(GO) build -o bin/mercutio ./cmd/mercutio
	cd nodeagent && $(GO) build -o ../bin/mercutio-nodeagent ./cmd/mercutio-nodeagent
	cd nodeagent && $(GO) build -o ../bin/mercutio-artifacts ./cmd/mercutio-artifacts

nodeagent-generate:
	cd nodeagent && $(HZN) workbench -compile -o generated programs/mercutio.hzn

nodeagent-check-generated:
	rm -rf nodeagent/tmp-generated
	cd nodeagent && $(HZN) workbench -o tmp-generated programs/mercutio.hzn
	diff -u nodeagent/generated/mercutio.bindings.go nodeagent/tmp-generated/mercutio.bindings.go
	diff -u nodeagent/generated/mercutio.bpf.c nodeagent/tmp-generated/mercutio.bpf.c
	diff -u nodeagent/generated/mercutio.cap.json nodeagent/tmp-generated/mercutio.cap.json
	diff -u nodeagent/generated/mercutio.diagnostics.json nodeagent/tmp-generated/mercutio.diagnostics.json
	diff -u nodeagent/generated/mercutio.hznmap.json <(sed 's#tmp-generated/#generated/#g' nodeagent/tmp-generated/mercutio.hznmap.json)
	rm -rf nodeagent/tmp-generated

helm-check:
	helm lint deploy/helm/mercutio $(HELM_TEST_ARGS)
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) >/dev/null

helm-manifest:
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) > deploy/manifests/mercutio.yaml

helm-manifest-check:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) > "$$tmp"; \
	diff -u deploy/manifests/mercutio.yaml "$$tmp"

profile-check:
	$(GO) run ./cmd/mercutio-profile -check -horizon-manifest nodeagent/generated/mercutio.cap.json

check: dependency-check module-boundary-check ui-check test race vet build nodeagent-check-generated profile-check helm-check helm-manifest-check
