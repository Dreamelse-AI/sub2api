#!/usr/bin/env bash
# 把 sub2api 应用清单 apply 到 popop-test 集群的 sub2api 命名空间，并滚动到指定镜像。
#
#   ./deploy/k8s/popop-test/apply.sh <image[:tag]>
#
# 仅管理应用本体（configmap / certificate / service / ingress / deployment）；
# postgres / redis / PVC / sub2api-secrets 是已有的有状态资源，不在此脚本范围内。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBECONFIG_FILE="${KUBECONFIG_FILE:-$HOME/.kube/popop-test.yaml}"
NAMESPACE="sub2api"
IMAGE="${1:-}"

if [[ -z "$IMAGE" ]]; then
  echo "usage: $0 <image[:tag]>" >&2
  exit 1
fi

k() { kubectl --kubeconfig "$KUBECONFIG_FILE" -n "$NAMESPACE" "$@"; }

k apply -f "$SCRIPT_DIR/configmap.yaml"
k apply -f "$SCRIPT_DIR/certificate.yaml"
k apply -f "$SCRIPT_DIR/service.yaml"
k apply -f "$SCRIPT_DIR/ingress.yaml"
k apply -f "$SCRIPT_DIR/deployment.yaml"
if [[ -f "$SCRIPT_DIR/feishu-secret.yaml" ]]; then
  k apply -f "$SCRIPT_DIR/feishu-secret.yaml"
fi

k set image deployment/sub2api "sub2api=$IMAGE"
k rollout status deployment/sub2api --timeout=300s
k get pods -l app.kubernetes.io/component=app -o wide
