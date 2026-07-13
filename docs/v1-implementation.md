# Mercutio v1 implementation map

This document keeps the first trunk honest against the normative design in `hypha://m31labs/mercutio/object/spec.mercutio.v1-design`.

| Hyphae design area | First-trunk implementation | Production adapter still required |
| --- | --- | --- |
| Cell = Kubernetes pod | `internal/cell.Store`, Helm sandbox template, pod RBAC | Cell reconciler, graft worktree init, agent image, teardown controller |
| Arbiter → Continuum → Horizon | `sandboxProfile` is carried on every cell and displayed in the viewport | Profile compilation, Continuum manifests, Horizon attach and event ingestion |
| Two-level observability | `model.Event`, intent/kernel feeds, client divergence indicator | Hyphae trace client and Horizon ringbuf consumer; no self-report is treated as kernel truth |
| GoSX hubs/CRDT | `internal/transport`, per-file `crdt.Doc`, hub updates and presence | Browser binary CRDT sync bridge and durable document snapshots |
| Graft entity review → Buckley commit | Review card and approve mutation | Entity diff provider, commit authorization, commit receipt |
| gotreesitter intelligence | Language metadata plus lightweight outline fallback in the viewport | gotreesitter incremental parse/highlighting/tagger package integration, starting with YAML/TOML/JSON/HCL and house DSLs |
| Browser viewport | GoSX SSR shell, full textarea editing, prompt composer, live feeds | Authenticated magic-link/passkey flow, richer editor surface, secret broker |
| Orrery fleet view | Toggleable fleet panel inside the viewport | Repository/cell graph and canopy overlays |

## Deliberate v1 boundaries

The trunk does not add a terminal, debugger, extension marketplace, task queue, multi-agent assignment, mobile shell, or multi-tenant organization model. Those are explicit out-of-scope items in the Hyphae design.

The local control plane is not a security boundary. Set `MERCUTIO_DEV_MODE=0` and provide `MERCUTIO_OPERATOR_TOKEN` outside local development. Secrets must be injected through Kubernetes Secrets/vault and a future broker; they must not be written into CRDT broadcasts or agent files.

## Next implementation order

1. Wire the cell reconciler to the Helm sandbox template and record pod lifecycle events.
2. Consume Horizon kernel events beside Hyphae trace ticks, preserving their independent timestamps and sources.
3. Replace the review fixture with graft entity diffs and a Buckley commit receipt.
4. Add the gotreesitter adapter and make policy/config languages the first-class intelligence path.
5. Move state snapshots to a durable store and enable binary CRDT sync in the browser.
