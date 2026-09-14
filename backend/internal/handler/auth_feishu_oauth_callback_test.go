package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/authidentity"
	dbuser "github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// newFeishuUpstream 模拟飞书 authen/v2/oauth/token + authen/v1/user_info。
// userInfoData 是 user_info 响应里的 data 字段原文（JSON）。
func newFeishuUpstream(t *testing.T, userInfoData string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/authen/v2/oauth/token":
			_, _ = w.Write([]byte(`{"code":0,"access_token":"u-feishu-access","token_type":"Bearer","expires_in":7200}`))
		case "/open-apis/authen/v1/user_info":
			require.Equal(t, "Bearer u-feishu-access", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":` + userInfoData + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func newFeishuOAuthHandlerAndClient(t *testing.T, invitationEnabled bool, upstreamURL string) (*AuthHandler, *dbent.Client) {
	t.Helper()
	handler, client := newOAuthPendingFlowTestHandler(t, invitationEnabled)
	handler.settingSvc = nil
	handler.cfg = &config.Config{
		JWT: config.JWTConfig{
			Secret:                   "test-secret",
			ExpireHour:               1,
			AccessTokenExpireMinutes: 60,
			RefreshTokenExpireDays:   7,
		},
		Feishu: config.FeishuConnectConfig{
			Enabled:             true,
			ClientID:            "cli_test",
			ClientSecret:        "feishu-secret",
			AuthorizeURL:        upstreamURL + "/open-apis/authen/v1/authorize",
			TokenURL:            upstreamURL + "/open-apis/authen/v2/oauth/token",
			UserInfoURL:         upstreamURL + "/open-apis/authen/v1/user_info",
			RedirectURL:         "https://api.example.com/api/v1/auth/oauth/feishu/callback",
			FrontendRedirectURL: "/auth/feishu/callback",
			RequireEmail:        false,
		},
	}
	return handler, client
}

func newFeishuCallbackRequest(intent string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/feishu/callback?code=code-feishu&state=state-feishu", nil)
	req.AddCookie(encodedCookie(feishuOAuthStateCookieName, "state-feishu"))
	req.AddCookie(encodedCookie(feishuOAuthRedirectCookie, "/dashboard"))
	req.AddCookie(encodedCookie(feishuOAuthIntentCookieName, intent))
	req.AddCookie(encodedCookie(oauthPendingBrowserCookieName, "browser-feishu"))
	return req
}

// 飞书未返回邮箱 + require_email=false + 无需邀请码/邮箱验证：回调应直接用合成邮箱注册并下发 token，
// 而不是留下一个永远无法完成的 pending session。
func TestFeishuOAuthCallbackDirectlyLogsInNewUserWithoutEmail(t *testing.T) {
	upstream := newFeishuUpstream(t, `{"name":"张三","en_name":"Zhang San","open_id":"ou_direct","union_id":"on_direct","user_id":"u1","tenant_key":"t1","avatar_url":"https://cdn.example/feishu.png"}`)
	defer upstream.Close()

	handler, client := newFeishuOAuthHandlerAndClient(t, false, upstream.URL)
	t.Cleanup(func() { _ = client.Close() })

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = newFeishuCallbackRequest(oauthIntentLogin)

	handler.FeishuOAuthCallback(c)

	require.Equal(t, http.StatusFound, recorder.Code)
	location := recorder.Header().Get("Location")
	require.Contains(t, location, "/auth/feishu/callback#")
	require.Contains(t, location, "access_token=")
	require.Contains(t, location, "refresh_token=")
	fragmentValues := parseOAuthRedirectFragment(t, location)
	require.Equal(t, "/dashboard", fragmentValues.Get("redirect"))
	requireCookieCleared(t, recorder, oauthPendingSessionCookieName)
	requireCookieCleared(t, recorder, oauthPendingBrowserCookieName)

	ctx := context.Background()
	userEntity, err := client.User.Query().
		Where(dbuser.EmailEQ("feishu-on_direct@feishu-connect.invalid")).
		Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "张三", userEntity.Username)
	require.Equal(t, "feishu", userEntity.SignupSource)

	identity, err := client.AuthIdentity.Query().
		Where(
			authidentity.ProviderTypeEQ("feishu"),
			authidentity.ProviderKeyEQ("feishu"),
			authidentity.ProviderSubjectEQ("on_direct"),
		).
		Only(ctx)
	require.NoError(t, err)
	require.Equal(t, userEntity.ID, identity.UserID)
	require.Equal(t, "https://cdn.example/feishu.png", identity.Metadata["suggested_avatar_url"])

	sessionCount, err := client.PendingAuthSession.Query().Count(ctx)
	require.NoError(t, err)
	require.Zero(t, sessionCount)
}

// 第二次用同一飞书账号登录：auth_identities 命中，走 pending session 登录终态（exchange 会下发 token）。
func TestFeishuOAuthCallbackSecondLoginHitsExistingIdentity(t *testing.T) {
	upstream := newFeishuUpstream(t, `{"name":"张三","open_id":"ou_direct","union_id":"on_direct"}`)
	defer upstream.Close()

	handler, client := newFeishuOAuthHandlerAndClient(t, false, upstream.URL)
	t.Cleanup(func() { _ = client.Close() })

	first := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(first)
	c1.Request = newFeishuCallbackRequest(oauthIntentLogin)
	handler.FeishuOAuthCallback(c1)
	require.Equal(t, http.StatusFound, first.Code)
	require.Contains(t, first.Header().Get("Location"), "access_token=")

	second := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(second)
	c2.Request = newFeishuCallbackRequest(oauthIntentLogin)
	handler.FeishuOAuthCallback(c2)
	require.Equal(t, http.StatusFound, second.Code)

	ctx := context.Background()
	session, err := client.PendingAuthSession.Query().Only(ctx)
	require.NoError(t, err)
	require.Equal(t, oauthIntentLogin, session.Intent)
	require.Equal(t, "feishu", session.ProviderType)
	require.NotNil(t, session.TargetUserID)
	userEntity, err := client.User.Query().Where(dbuser.EmailEQ("feishu-on_direct@feishu-connect.invalid")).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, userEntity.ID, *session.TargetUserID)

	userCount, err := client.User.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, userCount, "second login must not create another user")
}

// 需要邀请码时不能直接注册：回落到 choice pending session，由前端引导填邀请码创建账户。
func TestFeishuOAuthCallbackCreatesChoicePendingSessionWhenSignupRequiresInvite(t *testing.T) {
	upstream := newFeishuUpstream(t, `{"name":"张三","open_id":"ou_invite","union_id":"on_invite"}`)
	defer upstream.Close()

	handler, client := newFeishuOAuthHandlerAndClient(t, true, upstream.URL)
	t.Cleanup(func() { _ = client.Close() })

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = newFeishuCallbackRequest(oauthIntentLogin)

	handler.FeishuOAuthCallback(c)

	require.Equal(t, http.StatusFound, recorder.Code)
	require.NotContains(t, recorder.Header().Get("Location"), "access_token=")

	ctx := context.Background()
	session, err := client.PendingAuthSession.Query().Only(ctx)
	require.NoError(t, err)
	require.Nil(t, session.TargetUserID)
	payload, ok := readCompletionResponse(session.LocalFlowState)
	require.True(t, ok)
	require.Equal(t, oauthPendingChoiceStep, payload["step"])
	require.Equal(t, "feishu-on_invite@feishu-connect.invalid", payload["email"])

	userCount, err := client.User.Query().Count(ctx)
	require.NoError(t, err)
	require.Zero(t, userCount)
}
