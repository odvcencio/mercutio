#!/usr/bin/env bash
set -euo pipefail

digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
helm install mercutio deploy/helm/mercutio --namespace mercutio-system --create-namespace --include-crds \
  --set image.digest="$digest" --set nodeAgent.image.digest="$digest" \
  --set sandbox.agentImage="example.invalid/agent@$digest" \
  --set sandbox.attachImage="example.invalid/mercutio@$digest" \
  --set sandbox.graftImage="example.invalid/graft@$digest" \
  --set sandbox.armgateImage="example.invalid/mercutio@$digest"

kubectl get crd cells.mercutio.dev
for profile in strict standard open; do
  namespace="mercutio-cell-$profile"
  kubectl get namespace "$namespace"
  kubectl -n "$namespace" get networkpolicy mercutio-default-deny-all
  kubectl -n "$namespace" get resourcequota mercutio-cells
  kubectl -n "$namespace" auth can-i create pods --as=system:serviceaccount:mercutio-system:mercutio | grep -qx yes
done
kubectl -n mercutio-system get deployment mercutio
kubectl -n mercutio-system get daemonset mercutio-nodeagent
