# Mercutio Helm chart

The chart installs the non-privileged GoSX control plane and the resources it needs to reconcile sandbox pods. `horizon.enabled` is false by default. Enabling it is an explicit security decision because the enforcement DaemonSet needs privileged eBPF attachment capabilities.

Create the operator secret before installing in a non-development environment:

```sh
kubectl create secret generic mercutio-operator-token --from-literal=token="$MERCUTIO_OPERATOR_TOKEN"
helm install mercutio ./deploy/helm/mercutio
```

The sandbox pod is supplied as a ConfigMap template so the reconciler can inject cell-specific repo, branch, hub, and profile values. The chart does not create agent pods until that reconciler is enabled.
