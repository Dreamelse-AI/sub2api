package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// feishuClientConfig 是 FeishuClient 需要的最小配置子集。
type feishuClientConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	UserInfoURL  string
	RedirectURL  string
}

// FeishuClient 封装飞书（Lark）"网页应用登录"两步调用：
//  1. authen/v2/oauth/token：用授权码换 user_access_token（JSON body，非标准 form）
//  2. authen/v1/user_info：用 user_access_token 拉取登录用户信息
//
// 与 SigNoz 飞书 SSO 实现保持相同的端点和语义，可复用同一个飞书应用。
type FeishuClient struct {
	cfg        feishuClientConfig
	httpClient *http.Client
}

const feishuMaxResponseBytes int64 = 1 << 20

// FeishuAPIError 表示飞书开放平台返回的业务错误（code != 0 或 HTTP 非 2xx）。
type FeishuAPIError struct {
	Code    int
	Message string
	HTTP    int
}

func (e *FeishuAPIError) Error() string {
	return fmt.Sprintf("feishu api error code=%d msg=%s http=%d", e.Code, e.Message, e.HTTP)
}

// FeishuUserInfo 是 authen/v1/user_info 的 data 字段子集。
type FeishuUserInfo struct {
	OpenID          string `json:"open_id"`
	UnionID         string `json:"union_id"`
	UserID          string `json:"user_id"`
	TenantKey       string `json:"tenant_key"`
	Name            string `json:"name"`
	EnName          string `json:"en_name"`
	Email           string `json:"email"`
	EnterpriseEmail string `json:"enterprise_email"`
	AvatarURL       string `json:"avatar_url"`
}

// Subject 返回作为 auth_identities.provider_subject 的稳定主键。
// union_id 在同一开发者主体下跨应用稳定，优先使用；没有时退化到 open_id（app 内稳定）。
func (u *FeishuUserInfo) Subject() string {
	if u == nil {
		return ""
	}
	if v := strings.TrimSpace(u.UnionID); v != "" {
		return v
	}
	return strings.TrimSpace(u.OpenID)
}

// PreferredEmail 返回企业邮箱，其次个人邮箱；都没有返回空串。
func (u *FeishuUserInfo) PreferredEmail() string {
	if u == nil {
		return ""
	}
	if v := strings.TrimSpace(u.EnterpriseEmail); v != "" {
		return v
	}
	return strings.TrimSpace(u.Email)
}

// DisplayName 返回中文名，其次英文名。
func (u *FeishuUserInfo) DisplayName() string {
	if u == nil {
		return ""
	}
	if v := strings.TrimSpace(u.Name); v != "" {
		return v
	}
	return strings.TrimSpace(u.EnName)
}

type feishuTokenResponse struct {
	Code             int    `json:"code"`
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Msg              string `json:"msg"`
}

// ExchangeCodeForUserToken 用授权码换取 user_access_token。
func (c *FeishuClient) ExchangeCodeForUserToken(ctx context.Context, code string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.cfg.ClientID,
		"client_secret": c.cfg.ClientSecret,
		"code":          code,
		"redirect_uri":  c.cfg.RedirectURL,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, feishuMaxResponseBytes))
	var out feishuTokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", &FeishuAPIError{Code: -1, Message: "invalid token response: " + err.Error(), HTTP: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.Code != 0 || strings.TrimSpace(out.AccessToken) == "" {
		msg := strings.TrimSpace(out.ErrorDescription)
		if msg == "" {
			msg = strings.TrimSpace(out.Msg)
		}
		if msg == "" {
			msg = strings.TrimSpace(out.Error)
		}
		if msg == "" {
			msg = "failed to get user access token"
		}
		return "", &FeishuAPIError{Code: out.Code, Message: msg, HTTP: resp.StatusCode}
	}
	return out.AccessToken, nil
}

type feishuUserInfoResponse struct {
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Data FeishuUserInfo `json:"data"`
}

// GetUserInfo 用 user_access_token 拉取登录用户信息。
func (c *FeishuClient) GetUserInfo(ctx context.Context, accessToken string) (*FeishuUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, feishuMaxResponseBytes))
	var out feishuUserInfoResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &FeishuAPIError{Code: -1, Message: "invalid user info response: " + err.Error(), HTTP: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.Code != 0 {
		msg := strings.TrimSpace(out.Msg)
		if msg == "" {
			msg = "failed to get user info"
		}
		return nil, &FeishuAPIError{Code: out.Code, Message: msg, HTTP: resp.StatusCode}
	}
	info := out.Data
	if info.Subject() == "" {
		return nil, &FeishuAPIError{Code: -1, Message: "user info carries neither union_id nor open_id", HTTP: resp.StatusCode}
	}
	return &info, nil
}
