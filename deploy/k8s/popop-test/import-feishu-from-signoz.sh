#!/usr/bin/env bash
# 把 popop-test 集群里 SigNoz（ns signoz, pod signoz-0）已配置的飞书 SSO 应用（App ID / App Secret）
# 原样导入为 sub2api 的 k8s Secret `sub2api-feishu`，并启用飞书登录、重启 sub2api。
#
#   ./deploy/k8s/popop-test/import-feishu-from-signoz.sh
#
# 全程不在终端打印 App Secret：sqlite 库先拷到 mktemp 目录（0700），Python 解析后直接以 stdin 喂给
# kubectl apply，脚本退出时删除临时文件。只会打印 SigNoz 里的 auth domain 名、App ID 和 useLark 标记。
#
# 传输说明：这个集群的 `kubectl exec` 单次输出流在 ~200KB 处就会被掐断（unexpected EOF），
# `kubectl cp` 同样如此，所以这里先在 pod 里打成 tgz，再按 128KB 分块、每块一次 exec 拉回，
# 最后用 sha256 校验完整性。
#
# 依赖：kubectl（能访问 ~/.kube/popop-test.yaml）、python3（自带 sqlite3 模块）。

set -euo pipefail

KUBECONFIG_FILE="${KUBECONFIG_FILE:-$HOME/.kube/popop-test.yaml}"
SIGNOZ_NS="${SIGNOZ_NS:-signoz}"
SIGNOZ_POD="${SIGNOZ_POD:-signoz-0}"
SIGNOZ_DATA_DIR="${SIGNOZ_DATA_DIR:-/var/lib/signoz}"
NAMESPACE="sub2api"
CHUNK=131072          # 128KB，低于该集群 exec 流 ~200KB 的截断阈值
REMOTE_TGZ="/tmp/sub2api-feishu-export.$$.tgz"

k() { kubectl --kubeconfig "$KUBECONFIG_FILE" "$@"; }
kx() { k -n "$SIGNOZ_NS" exec "$SIGNOZ_POD" -c signoz -- "$@"; }

TMP="$(mktemp -d)"
chmod 700 "$TMP"
cleanup() {
  rm -rf "$TMP"
  kx rm -f "$REMOTE_TGZ" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">> 在 $SIGNOZ_NS/$SIGNOZ_POD 内打包 SigNoz sqlite 库（db + WAL）"
META="$(kx sh -c "cd '$SIGNOZ_DATA_DIR' && files=signoz.db; [ -f signoz.db-wal ] && files=\"\$files signoz.db-wal\"; tar czf '$REMOTE_TGZ' \$files && printf '%s %s\n' \"\$(wc -c < '$REMOTE_TGZ')\" \"\$(sha256sum '$REMOTE_TGZ' | cut -d' ' -f1)\"")"
SIZE="${META%% *}"
REMOTE_SHA="${META##* }"
echo "   远端 tgz 大小 ${SIZE} 字节"

echo ">> 按 ${CHUNK} 字节分块拉回（每块一次 exec，失败自动重试）"
: > "$TMP/export.tgz"
i=0
while [ $((i * CHUNK)) -lt "$SIZE" ]; do
  ok=0
  for attempt in 1 2 3; do
    if kx sh -c "dd if='$REMOTE_TGZ' bs=$CHUNK skip=$i count=1 2>/dev/null" > "$TMP/chunk" 2>/dev/null \
       && [ -s "$TMP/chunk" ]; then
      cat "$TMP/chunk" >> "$TMP/export.tgz"
      ok=1
      break
    fi
    sleep 1
  done
  if [ "$ok" -ne 1 ]; then
    echo "!! 第 $i 块拉取连续失败 3 次，中止" >&2
    exit 1
  fi
  i=$((i + 1))
  printf '\r   已拉取 %d 块' "$i"
done
echo

LOCAL_SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/export.tgz")"
if [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
  echo "!! sha256 不一致：remote=$REMOTE_SHA local=$LOCAL_SHA（本地 $(wc -c < "$TMP/export.tgz") 字节）" >&2
  exit 1
fi
echo "   sha256 校验通过"
tar xzf "$TMP/export.tgz" -C "$TMP"

echo ">> 解析 auth_domain 表中的飞书 SSO 配置并生成 Secret 清单"
python3 - "$TMP" <<'PY' > "$TMP/secret.yaml"
import json, sqlite3, sys

tmp = sys.argv[1]
con = sqlite3.connect(f"{tmp}/signoz.db")
rows = con.execute("select name, data from auth_domain").fetchall()

candidates = []
for name, data in rows:
    try:
        cfg = json.loads(data or "{}")
    except json.JSONDecodeError:
        continue
    if cfg.get("ssoType") != "feishu" or not cfg.get("feishuConfig"):
        continue
    candidates.append((name, cfg))

if not candidates:
    sys.stderr.write("!! SigNoz 的 auth_domain 表里没有 ssoType=feishu 的域，无法导入\n")
    sys.exit(1)

# 优先 ssoEnabled=true 的域
candidates.sort(key=lambda c: (not c[1].get("ssoEnabled", False), c[0]))
name, cfg = candidates[0]
feishu = cfg["feishuConfig"]
client_id = (feishu.get("clientId") or "").strip()
client_secret = (feishu.get("clientSecret") or "").strip()
use_lark = bool(feishu.get("useLark", False))
if not client_id or not client_secret:
    sys.stderr.write(f"!! auth domain {name!r} 的 feishuConfig 缺少 clientId/clientSecret\n")
    sys.exit(1)

sys.stderr.write(f"   auth domain: {name}\n   App ID: {client_id}\n   useLark: {use_lark}\n")

secret = {
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {
        "name": "sub2api-feishu",
        "namespace": "sub2api",
        "labels": {"app.kubernetes.io/part-of": "sub2api"},
        "annotations": {"sub2api.popop.ai/imported-from": f"signoz auth_domain {name}"},
    },
    "type": "Opaque",
    "stringData": {
        "FEISHU_CONNECT_ENABLED": "true",
        "FEISHU_CONNECT_CLIENT_ID": client_id,
        "FEISHU_CONNECT_CLIENT_SECRET": client_secret,
        "FEISHU_USE_LARK": "true" if use_lark else "false",
    },
}
json.dump(secret, sys.stdout)
PY
chmod 600 "$TMP/secret.yaml"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo ">> DRY_RUN=1：已成功解析出飞书配置，不写 Secret、不重启。"
  exit 0
fi

echo ">> 写入 Secret $NAMESPACE/sub2api-feishu"
k -n "$NAMESPACE" apply -f "$TMP/secret.yaml"

# 国际版 Lark 应用要换 larksuite 端点；国内飞书保持 configmap 默认值
USE_LARK="$(k -n "$NAMESPACE" get secret sub2api-feishu -o jsonpath='{.data.FEISHU_USE_LARK}' | base64 -d)"
if [[ "$USE_LARK" == "true" ]]; then
  echo ">> useLark=true，切换 configmap 到 Lark 国际版端点"
  k -n "$NAMESPACE" patch configmap sub2api-config --type merge -p '{"data":{
    "FEISHU_CONNECT_AUTHORIZE_URL":"https://accounts.larksuite.com/open-apis/authen/v1/authorize",
    "FEISHU_CONNECT_TOKEN_URL":"https://open.larksuite.com/open-apis/authen/v2/oauth/token",
    "FEISHU_CONNECT_USERINFO_URL":"https://open.larksuite.com/open-apis/authen/v1/user_info"}}'
fi

echo ">> 重启 sub2api 以加载凭据"
k -n "$NAMESPACE" rollout restart deployment/sub2api
k -n "$NAMESPACE" rollout status deployment/sub2api --timeout=300s

echo ">> 验证公开设置里的飞书开关（ALB 切到新 Pod 可能需要几十秒，最多等 90s）"
verified=0
for attempt in $(seq 1 18); do
  body="$(curl -s -m 15 https://sub2api.popop.ai/api/v1/settings/public || true)"
  flag="$(printf '%s' "$body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
d = d.get("data", d)
v = d.get("feishu_oauth_enabled")
if v is not None:
    print(str(v).lower())
' 2>/dev/null || true)"
  if [[ "$flag" == "true" ]]; then
    echo "   feishu_oauth_enabled = true"
    verified=1
    break
  fi
  sleep 5
done
if [[ "$verified" -ne 1 ]]; then
  echo "   !! 90s 内没有从 https://sub2api.popop.ai 读到 feishu_oauth_enabled=true（最后一次响应: ${body:0:200})" >&2
  echo "   Secret 已写入、Pod 已重启，可稍后手动检查：curl -s https://sub2api.popop.ai/api/v1/settings/public | grep -o '\"feishu_oauth_enabled\":[a-z]*'" >&2
fi

cat <<'EOF'

完成。还需在飞书开放平台 → 该应用 → 安全设置 → 重定向 URL 里登记：
  https://sub2api.popop.ai/api/v1/auth/oauth/feishu/callback
否则飞书会在授权页报 redirect_uri 不合法。
EOF
