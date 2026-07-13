# Mercutio

Mercutio is a sandbox-first home for coding agents. It is built around a watching-first viewport: the operator sees what an agent claims, what the kernel observed, and the structural diff that is ready for approval.

This repository is the first public trunk for the Mercutio v1 design recorded in the [Mercutio Hyphae space](https://github.com/odvcencio/mercutio). The implementation is intentionally a vertical slice that can run locally today and has Kubernetes seams for the production control plane.

## What works in this trunk

- GoSX server-rendered browser viewport with an uncompromised textarea editor.
- Cell lifecycle: create from repository + branch, inspect, steer, and stop.
- Per-file GoSX CRDT documents, with the v1 snapshot API and hub transport in front of them.
- Prompting the cell agent from the viewport.
- Presence and live cell updates over a GoSX WebSocket hub.
- Side-by-side intent/trace and kernel/Horizon event feeds, including divergence alerting.
- Entity-level review card with an approve handoff for the future Buckley commit adapter.
- Single-operator development mode plus bearer-token production boundary.
- Helm chart with control-plane deployment, namespace quota, sandbox RBAC/template, and an opt-in Horizon DaemonSet.

The local store is deliberately ephemeral. It makes the product loop testable before Kubernetes, Horizon, graft, Buckley, and Hyphae trace clients are wired to their production transports.

## Run locally

```sh
go run ./cmd/mercutio
# open http://127.0.0.1:9011
```

Local development is open by default. For a production-like local run:

```sh
MERCUTIO_DEV_MODE=0 MERCUTIO_OPERATOR_TOKEN=change-me go run ./cmd/mercutio
```

The browser UI is intentionally browser-first. Desktop/mobile shells and terminal/debugger surfaces are outside v1.

## Checks

```sh
go test ./...
go vet ./...
node --check public/app.js
go build ./cmd/mercutio
```

## Kubernetes

The chart is under `deploy/helm/mercutio`:

```sh
helm template mercutio deploy/helm/mercutio \
  --set image.repository=ghcr.io/odvcencio/mercutio
```

The default chart keeps `horizon.enabled=false`. Enabling Horizon requires a deliberate security review because the DaemonSet needs privileged eBPF attachment capabilities. The sandbox template is a ConfigMap consumed by the future cell reconciler; it is not a privileged pod factory hidden in the chart.

## Architecture

```text
browser viewport
      │  GoSX page + WebSocket hub
      ▼
control plane ── cell store + CRDT docs ── review/trace adapters
      │
      ├── graft worktree init → agent sandbox pod
      ├── Arbiter policy → Continuum manifest
      └── Horizon eBPF DaemonSet → kernel event feed
```

See [`docs/v1-implementation.md`](docs/v1-implementation.md) for the design-to-code map and explicit follow-up boundaries.

## License

MIT. See [`LICENSE`](LICENSE).
