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
	@test "$$($(GO) list -m -f '{{if eq .Path "m31labs.dev/gosx"}}{{.Version}}{{end}}' all)" = "v0.31.5"
	@test "$$($(GO) list -m -f '{{if eq .Path "m31labs.dev/gosx/editor"}}{{.Version}}{{end}}' all)" = "v0.19.10"
	@test "$$($(GO) list -m -f '{{if eq .Path "github.com/odvcencio/gotreesitter"}}{{.Version}}{{end}}' all)" = "v0.36.1-0.20260714033649-d6d2b55978ef"
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
	rm -rf nodeagent/tmp-generated-a nodeagent/tmp-generated-b
	cd nodeagent && $(HZN) workbench -compile -o tmp-generated-a programs/mercutio.hzn
	cd nodeagent && $(HZN) workbench -compile -o tmp-generated-b programs/mercutio.hzn
	diff -u nodeagent/generated/mercutio.bindings.go nodeagent/tmp-generated-a/mercutio.bindings.go
	diff -u nodeagent/generated/mercutio.bpf.c nodeagent/tmp-generated-a/mercutio.bpf.c
	diff -u nodeagent/generated/mercutio.cap.json nodeagent/tmp-generated-a/mercutio.cap.json
	diff -u nodeagent/generated/mercutio.diagnostics.json nodeagent/tmp-generated-a/mercutio.diagnostics.json
	diff -u nodeagent/generated/mercutio.hznmap.json <(sed 's#tmp-generated-a/#generated/#g' nodeagent/tmp-generated-a/mercutio.hznmap.json)
	cmp nodeagent/tmp-generated-a/mercutio.bpf.o nodeagent/tmp-generated-b/mercutio.bpf.o
	@! strings nodeagent/generated/mercutio.bpf.o | grep -F "$(CURDIR)"
	rm -rf nodeagent/tmp-generated-a nodeagent/tmp-generated-b

helm-check:
	helm lint deploy/helm/mercutio $(HELM_TEST_ARGS)
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) >/dev/null
	@! helm template mercutio deploy/helm/mercutio --set replicaCount=2 $(HELM_TEST_ARGS) >/dev/null 2>&1

helm-manifest:
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) > deploy/manifests/mercutio.yaml

helm-manifest-check:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	helm template mercutio deploy/helm/mercutio --include-crds $(HELM_TEST_ARGS) > "$$tmp"; \
	diff -u deploy/manifests/mercutio.yaml "$$tmp"

profile-check:
	$(GO) run ./cmd/mercutio-profile -check -horizon-manifest nodeagent/generated/mercutio.cap.json

check: dependency-check module-boundary-check ui-check test race vet build nodeagent-check-generated profile-check helm-check helm-manifest-check
