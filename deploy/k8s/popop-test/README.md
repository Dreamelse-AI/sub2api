# sub2api on popop-test (ACK) — namespace `sub2api`

这些清单描述 popop-test 集群 `sub2api` 命名空间里 **应用本体** 的部署（Deployment / Service / Ingress / ConfigMap / Certificate）。
`postgres`、`redis` 两个 Deployment 及三块 PVC（`postgres-data` / `redis-data` / `sub2api-data`）和 `sub2api-secrets`
是集群上已有的有状态资源，不在这里管理，`apply.sh` 不会动它们。

| 项目 | 值 |
| --- | --- |
| kubeconfig | `~/.kube/popop-test.yaml` |
| 域名 | `https://sub2api.popop.ai`（ALB ingress + cert-manager `letsencrypt-prod`） |
| 镜像仓库 | `wjm20260616-registry.ap-northeast-1.cr.aliyuncs.com/popop-i18n-test/data-test`（tag 前缀 `sub2api-`；ACR 里尚无独立的 `popop-i18n-test/sub2api` 仓库，建好后改回即可） |
| 节点架构 | linux/amd64（本机 arm64 需 `docker buildx --platform linux/amd64`） |

## 构建 + 部署

```bash
# 1) 构建并推送镜像（在仓库根目录）
IMG=wjm20260616-registry.ap-northeast-1.cr.aliyuncs.com/popop-i18n-test/data-test:sub2api-$(date +%Y%m%d%H%M)
docker buildx build --builder dreamboys-builder --platform linux/amd64 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) -t "$IMG" --push .

# 2) 应用清单并滚动到新镜像
./deploy/k8s/popop-test/apply.sh "$IMG"
```

`apply.sh` 会依次 `kubectl apply` configmap / certificate / service / ingress / deployment，然后
`kubectl set image` 到指定 tag 并等待 rollout 完成。

## 飞书登录

后端已内置飞书（Lark）OAuth provider（`feishu_connect.*` / `FEISHU_CONNECT_*`），端点与 SigNoz 的飞书 SSO 相同，
可复用同一个飞书应用。两种配置方式二选一：

1. **从 SigNoz 直接导入**（推荐）：`./deploy/k8s/popop-test/import-feishu-from-signoz.sh` 会把 popop-test 上 SigNoz
   已配置的飞书应用（`auth_domain` 表里 `ssoType=feishu` 的域）导入为 Secret `sub2api-feishu`、启用并重启，
   全程不打印 App Secret。
2. **后台设置页**（存 DB）：登录 sub2api 管理后台 → 系统设置 → 「飞书登录」→ 启用，填 App ID / App Secret，
   回调地址 `https://sub2api.popop.ai/api/v1/auth/oauth/feishu/callback`。
3. **手工 Secret**：按 `feishu-secret.example.yaml` 创建 `sub2api-feishu`，再 `rollout restart`。

无论哪种方式，都要在飞书开放平台该应用的「安全设置 → 重定向 URL」里登记上述回调地址，否则飞书会拒绝授权。
