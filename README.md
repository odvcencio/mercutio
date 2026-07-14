# Mercutio

Mercutio is a sandbox-first home for coding agents. Operators watch agent intent beside kernel observations, edit shared buffers directly, steer the active agent, and approve structural changes before they are committed.

## Capabilities

- GoSX browser viewport with repository cells, file tabs, multi-cursor editing, structural selection, definition navigation, incremental syntax highlighting, and policy-impact preview.
- Durable cell lifecycle backed by an in-memory runtime for local work and a Kubernetes Cell resource plus reconciled pods for deployed installations.
- Governed `strict`, `standard`, and recorded-not-contained `open` profiles compiled from Arbiter policy into signed Horizon enforcement artifacts.
- GoSX hub and CRDT documents for attributed agent presence, prompts, edits, actor-scoped undo, shadow revisions, and live viewport updates.
- Independent intent and kernel event feeds with divergence indication.
- Gotreesitter-based highlighting and symbol extraction without an LSP installation.
- Structural entity review cards with optional Buckley commit handoff.
- Single-operator bearer-token, magic-link, and passkey authentication paths.
- Redacted secret broker with receipt-only audit events; secret-shaped content is not commit-ready.
- Helm resources for the control plane, Cell CRD, sandbox template, resource quota, network-policy wall, and Horizon Node Agent enforcement.

## Run locally

```sh
go run ./cmd/mercutio
# open http://127.0.0.1:9011
```

Local development is open by default. To exercise the operator boundary:

```sh
MERCUTIO_DEV_MODE=0 MERCUTIO_OPERATOR_TOKEN=change-me go run ./cmd/mercutio
```

The agent bridge uses the same hub protocol as the browser:

```sh
go run ./cmd/mercutio attach \
  --cell cell-demo \
  --token "$MERCUTIO_ATTACH_TOKEN" \
  --hub http://127.0.0.1:9011/gosx/hub/agent
```

The bridge reads JSON events from stdin and writes prompts and bounded command results as JSON lines. Approved reviews are committed inside the cell through the pinned Buckley binary; command output is never relayed to the control plane.

## Kubernetes

The chart is under [`deploy/helm/mercutio`](deploy/helm/mercutio):

```sh
helm install mercutio deploy/helm/mercutio \
  --set image.digest="$MERCUTIO_IMAGE_DIGEST" \
  --set sandbox.agentImage="$MERCUTIO_AGENT_IMAGE" \
  --set sandbox.attachImage="$MERCUTIO_ATTACH_IMAGE" \
  --set sandbox.graftImage="$GRAFT_IMAGE" \
  --set sandbox.armgateImage="$MERCUTIO_ATTACH_IMAGE" \
  --set nodeAgent.image.digest="$MERCUTIO_NODEAGENT_DIGEST"
```

The required operator, session, event, capability, and Horizon trust Secrets must exist before installation; see the chart README for their exact keys. Images are accepted only by digest. The Node Agent is enabled by default and fails closed when its signed Horizon manifest, object, digest pins, kernel BTF, cgroup v2, or BPF-LSM prerequisites are missing. `mercutio doctor --require-r1` reports the host enforcement rung before installation.

## Checks

```sh
go test ./...
go vet ./...
go build ./cmd/mercutio
```

## License

MIT. See [`LICENSE`](LICENSE).
