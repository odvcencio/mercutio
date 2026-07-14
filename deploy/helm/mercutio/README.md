# Mercutio Helm chart

The chart installs the restricted GoSX control plane, Cell CRD, sandbox reconciler resources, lower-wall NetworkPolicies, and the Horizon Node Agent. Strict, standard, and open cells run in separate class namespaces, each with its own quota and default-deny policy. The Node Agent is enabled by default because contained cells must not start until their signed kernel policy is armed.

Create the runtime Secrets before installing. Use independent random values; do not reuse operator credentials as signing or event credentials.

```sh
kubectl create secret generic mercutio-operator-token --from-literal=token="$MERCUTIO_OPERATOR_TOKEN"
kubectl create secret generic mercutio-session-secret --from-literal=secret="$MERCUTIO_SESSION_SECRET"
kubectl create secret generic mercutio-event-token --from-literal=token="$MERCUTIO_EVENT_TOKEN"
kubectl create secret generic mercutio-capability-secret --from-literal=secret="$MERCUTIO_CAPABILITY_SECRET"
kubectl create secret generic mercutio-horizon-trust \
  --from-file=pins.json=./pins.json \
  --from-file=public-keys.json=./public-keys.json
kubectl create secret generic mercutio-internal-server-tls \
  --from-file=tls.crt=./server.crt --from-file=tls.key=./server.key \
  --from-file=ca.crt=./client-ca.crt
kubectl create secret generic mercutio-nodeagent-client-tls \
  --from-file=tls.crt=./nodeagent.crt --from-file=tls.key=./nodeagent.key \
  --from-file=ca.crt=./server-ca.crt
```

Set `operator.email` to the sole operator identity. Magic-link delivery is enabled only when `operator.smtp.address` and `operator.smtp.from` are set; authenticated SMTP additionally reads its password from `operator.smtp.passwordSecret`. Passkey registration requires an existing authenticated operator session, preventing an unauthenticated caller from claiming the configured identity.

The server certificate must cover `<release>-mercutio.<namespace>.svc`; the control plane requires and verifies a client certificate on its internal TLS 1.3 listener. Run `mercutio doctor --require-r1` on candidate nodes before scheduling the Node Agent. It requires Linux 5.10 or newer, kernel BTF, cgroup v2, and BPF-LSM in the active LSM list. The DaemonSet runs as UID 0 with only `BPF`, `PERFMON`, `NET_ADMIN`, and `SYS_RESOURCE`; it mounts bpffs read-write and cgroup/tracing state read-only. This is the chart's privileged trust boundary.

Supply digest-pinned values for the control plane, Node Agent, agent, attach/armgate, and Graft images. A restricted armgate init container receives a separate, short-lived arm capability and no workspace mount; the attach capability is mounted only into the attach sidecar. The workspace is a dedicated tmpfs device so file enforcement can use its kernel device identity. NetworkPolicy supplies the default-deny lower wall, and the signed Horizon policy supplies destination-aware enforcement. The `open` profile is explicitly recorded, not contained.
