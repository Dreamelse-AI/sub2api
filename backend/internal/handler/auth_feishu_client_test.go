package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeishuClient_ExchangeCodeForUserToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/open-apis/authen/v2/oauth/token", r.URL.Path)
		require.Contains(t, r.Header.Get("Content-Type"), "application/json")

		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		require.NoError(t, json.Unmarshal(raw, &body))
		require.Equal(t, "authorization_code", body["grant_type"])
		require.Equal(t, "cli_app", body["client_id"])
		require.Equal(t, "secret", body["client_secret"])
		require.Equal(t, "AUTH_CODE", body["code"])
		require.Equal(t, "https://sub2api.example.com/api/v1/auth/oauth/feishu/callback", body["redirect_uri"])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"access_token":"u-USER_TOKEN","token_type":"Bearer","expires_in":7200,"refresh_token":"ur-R"}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg: feishuClientConfig{
			ClientID:     "cli_app",
			ClientSecret: "secret",
			TokenURL:     server.URL + "/open-apis/authen/v2/oauth/token",
			RedirectURL:  "https://sub2api.example.com/api/v1/auth/oauth/feishu/callback",
		},
		httpClient: server.Client(),
	}
	token, err := cli.ExchangeCodeForUserToken(context.Background(), "AUTH_CODE")
	require.NoError(t, err)
	require.Equal(t, "u-USER_TOKEN", token)
}

func TestFeishuClient_ExchangeCodeForUserToken_ErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":20003,"error":"invalid_grant","error_description":"code is expired"}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg:        feishuClientConfig{ClientID: "k", ClientSecret: "s", TokenURL: server.URL + "/token"},
		httpClient: server.Client(),
	}
	_, err := cli.ExchangeCodeForUserToken(context.Background(), "BAD")
	require.Error(t, err)
	apiErr, ok := err.(*FeishuAPIError)
	require.True(t, ok)
	require.Equal(t, 20003, apiErr.Code)
	require.Equal(t, http.StatusBadRequest, apiErr.HTTP)
	require.Contains(t, apiErr.Message, "code is expired")
}

func TestFeishuClient_ExchangeCodeForUserToken_NonZeroCodeWith200(t *testing.T) {
	// 飞书在 HTTP 200 下也可能返回非 0 code，必须视为失败。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":20001,"error":"invalid_request","error_description":"redirect_uri mismatch"}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg:        feishuClientConfig{ClientID: "k", ClientSecret: "s", TokenURL: server.URL + "/token"},
		httpClient: server.Client(),
	}
	_, err := cli.ExchangeCodeForUserToken(context.Background(), "X")
	require.Error(t, err)
	apiErr, ok := err.(*FeishuAPIError)
	require.True(t, ok)
	require.Equal(t, 20001, apiErr.Code)
}

func TestFeishuClient_GetUserInfo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer u-USER_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"name":"张三","en_name":"Zhang San","avatar_url":"https://img.example.com/a.png","open_id":"ou_OPEN","union_id":"on_UNION","user_id":"uid1","tenant_key":"t1","email":"personal@example.com","enterprise_email":"zhangsan@corp.example.com"}}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg:        feishuClientConfig{UserInfoURL: server.URL + "/open-apis/authen/v1/user_info"},
		httpClient: server.Client(),
	}
	info, err := cli.GetUserInfo(context.Background(), "u-USER_TOKEN")
	require.NoError(t, err)
	require.Equal(t, "ou_OPEN", info.OpenID)
	require.Equal(t, "on_UNION", info.UnionID)
	require.Equal(t, "张三", info.Name)
	require.Equal(t, "https://img.example.com/a.png", info.AvatarURL)
	require.Equal(t, "on_UNION", info.Subject())
	require.Equal(t, "zhangsan@corp.example.com", info.PreferredEmail())
	require.Equal(t, "张三", info.DisplayName())
}

func TestFeishuClient_GetUserInfo_Fallbacks(t *testing.T) {
	info := &FeishuUserInfo{OpenID: "ou_ONLY", EnName: "Only En", Email: "p@example.com"}
	require.Equal(t, "ou_ONLY", info.Subject(), "no union_id → fall back to open_id")
	require.Equal(t, "p@example.com", info.PreferredEmail(), "no enterprise email → personal email")
	require.Equal(t, "Only En", info.DisplayName(), "no name → en_name")

	empty := &FeishuUserInfo{}
	require.Equal(t, "", empty.Subject())
	require.Equal(t, "", empty.PreferredEmail())
	require.Equal(t, "", empty.DisplayName())
}

func TestFeishuClient_GetUserInfo_ErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":99991668,"msg":"Invalid access token for authorization. Please make a request with token attached."}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg:        feishuClientConfig{UserInfoURL: server.URL + "/user_info"},
		httpClient: server.Client(),
	}
	_, err := cli.GetUserInfo(context.Background(), "bad")
	require.Error(t, err)
	apiErr, ok := err.(*FeishuAPIError)
	require.True(t, ok)
	require.Equal(t, 99991668, apiErr.Code)
	require.Contains(t, apiErr.Message, "Invalid access token")
}

func TestFeishuClient_GetUserInfo_MissingSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"name":"nobody"}}`))
	}))
	defer server.Close()

	cli := &FeishuClient{
		cfg:        feishuClientConfig{UserInfoURL: server.URL + "/user_info"},
		httpClient: server.Client(),
	}
	_, err := cli.GetUserInfo(context.Background(), "tok")
	require.Error(t, err, "user info without open_id/union_id cannot key an identity")
}
