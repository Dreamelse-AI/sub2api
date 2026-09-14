package handler

import (
	"net/url"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/stretchr/testify/require"
)

func TestBuildFeishuAuthorizeURL(t *testing.T) {
	cfg := config.FeishuConnectConfig{
		ClientID:     "cli_abc",
		AuthorizeURL: "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		RedirectURL:  "https://sub2api.example.com/api/v1/auth/oauth/feishu/callback",
	}
	raw, err := buildFeishuAuthorizeURL(cfg, "STATE123")
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "accounts.feishu.cn", u.Host)
	require.Equal(t, "/open-apis/authen/v1/authorize", u.Path)
	q := u.Query()
	require.Equal(t, "cli_abc", q.Get("client_id"))
	require.Equal(t, cfg.RedirectURL, q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "STATE123", q.Get("state"))
	require.Empty(t, q.Get("scope"), "scope is omitted when not configured")

	cfg.Scopes = "contact:user.email:readonly"
	raw, err = buildFeishuAuthorizeURL(cfg, "S")
	require.NoError(t, err)
	u, _ = url.Parse(raw)
	require.Equal(t, "contact:user.email:readonly", u.Query().Get("scope"))
}

func TestBuildFeishuAuthorizeURL_MissingConfig(t *testing.T) {
	_, err := buildFeishuAuthorizeURL(config.FeishuConnectConfig{RedirectURL: "https://x/cb"}, "s")
	require.Error(t, err)
	_, err = buildFeishuAuthorizeURL(config.FeishuConnectConfig{AuthorizeURL: "https://x/auth"}, "s")
	require.Error(t, err)
}

func TestBuildFeishuUpstreamClaims(t *testing.T) {
	info := &FeishuUserInfo{
		OpenID:          "ou_1",
		UnionID:         "on_1",
		UserID:          "u1",
		TenantKey:       "t1",
		Name:            "张三",
		EnName:          "Zhang San",
		Email:           "p@example.com",
		EnterpriseEmail: "z@corp.example.com",
		AvatarURL:       "https://img/a.png",
	}
	claims := buildFeishuUpstreamClaims(info)
	require.Equal(t, "z@corp.example.com", claims["email"])
	require.Equal(t, "张三", claims["username"])
	require.Equal(t, "on_1", claims["subject"])
	require.Equal(t, "ou_1", claims["open_id"])
	require.Equal(t, "on_1", claims["union_id"])
	require.Equal(t, "张三", claims["suggested_display_name"])
	require.Equal(t, "https://img/a.png", claims["suggested_avatar_url"])

	empty := buildFeishuUpstreamClaims(&FeishuUserInfo{OpenID: "ou_only"})
	require.Equal(t, "ou_only", empty["subject"])
	_, hasName := empty["suggested_display_name"]
	require.False(t, hasName)
	_, hasAvatar := empty["suggested_avatar_url"]
	require.False(t, hasAvatar)

	require.NotNil(t, buildFeishuUpstreamClaims(nil))
}

func TestBuildFeishuSyntheticEmail(t *testing.T) {
	require.Equal(t, "feishu-on_abc"+service.FeishuConnectSyntheticEmailDomain, buildFeishuSyntheticEmail(" ON_ABC "))
}

func TestIsThirdPartySyntheticEmail(t *testing.T) {
	require.True(t, isThirdPartySyntheticEmail("feishu-x"+service.FeishuConnectSyntheticEmailDomain))
	require.True(t, isThirdPartySyntheticEmail("dingtalk-x"+service.DingTalkConnectSyntheticEmailDomain))
	require.True(t, isThirdPartySyntheticEmail("linuxdo-x"+service.LinuxDoConnectSyntheticEmailDomain))
	require.True(t, isThirdPartySyntheticEmail("oidc-x"+service.OIDCConnectSyntheticEmailDomain))
	require.True(t, isThirdPartySyntheticEmail("wechat-x"+service.WeChatConnectSyntheticEmailDomain))
	require.False(t, isThirdPartySyntheticEmail("real@feishu.cn"))
	require.False(t, isThirdPartySyntheticEmail(""))
}

func TestFeishuBindLoginCompletionResponse(t *testing.T) {
	resp := feishuBindLoginCompletionResponse("/dashboard")
	require.Equal(t, "bind_login_required", resp["step"])
	require.Equal(t, true, resp["existing_account_bindable"])
	require.Equal(t, false, resp["create_account_allowed"])
	require.Equal(t, "/dashboard", resp["redirect"])
}
