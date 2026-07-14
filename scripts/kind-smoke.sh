#!/usr/bin/env bash
set -euo pipefail

digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
fullname="mercutio-mercutio"
cell_namespaces=(mercutio-cell-strict mercutio-cell-standard mercutio-cell-open)

cleanup() {
  helm uninstall mercutio -n mercutio-system >/dev/null 2>&1 || true
  kubectl delete namespace mercutio-system "${cell_namespaces[@]}" --ignore-not-found --wait=true >/dev/null
  kubectl delete crd cells.mercutio.dev --ignore-not-found --wait=true >/dev/null
}
trap cleanup EXIT
helm install mercutio deploy/helm/mercutio --namespace mercutio-system --create-namespace \
  --set image.digest="$digest" --set nodeAgent.image.digest="$digest" \
  --set sandbox.agentImage="example.invalid/agent@$digest" \
  --set sandbox.attachImage="example.invalid/mercutio@$digest" \
  --set sandbox.graftImage="example.invalid/graft@$digest" \
  --set sandbox.armgateImage="example.invalid/mercutio@$digest"

kubectl get crd cells.mercutio.dev
for profile in strict standard open; do
  namespace="mercutio-cell-$profile"
  kubectl get namespace "$namespace"
  kubectl -n "$namespace" get networkpolicy "$fullname-default-deny-all"
  kubectl -n "$namespace" get resourcequota "$fullname-cells"
  kubectl -n "$namespace" auth can-i create pods --as="system:serviceaccount:mercutio-system:$fullname" | grep -qx yes
done
kubectl -n mercutio-system get deployment "$fullname"
kubectl -n mercutio-system get daemonset "$fullname-nodeagent"

cleanup
trap - EXIT
test -z "$(kubectl get all,configmap,secret,serviceaccount,role,rolebinding,networkpolicy,resourcequota -A -l app.kubernetes.io/instance=mercutio -o name)"
! kubectl get crd cells.mercutio.dev >/dev/null 2>&1
