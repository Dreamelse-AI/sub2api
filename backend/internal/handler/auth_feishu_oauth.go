package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	dbuser "github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// ─── 常量 ──────────────────────────────────────────────────────────────────

const (
	feishuOAuthCookiePath         = "/api/v1/auth/oauth/feishu"
	feishuOAuthStateCookieName    = "feishu_oauth_state"
	feishuOAuthRedirectCookie     = "feishu_oauth_redirect"
	feishuOAuthIntentCookieName   = "feishu_oauth_intent"
	feishuOAuthBindUserCookieName = "feishu_oauth_bind_user"
	feishuOAuthCookieMaxAgeSec    = 600 // 10 分钟
	feishuOAuthDefaultRedirectTo  = "/dashboard"
	feishuOAuthDefaultFrontendCB  = "/auth/feishu/callback"

	feishuProviderType = "feishu"
)

// ─── Config helper ─────────────────────────────────────────────────────────

// getFeishuOAuthConfig 返回飞书 OAuth 最终生效配置。
// 优先从 settingSvc（settings 表）读取，回退到 h.cfg.Feishu。
func (h *AuthHandler) getFeishuOAuthConfig(ctx context.Context) (config.FeishuConnectConfig, error) {
	if h != nil && h.settingSvc != nil {
		return h.settingSvc.GetFeishuConnectOAuthConfig(ctx)
	}
	if h == nil || h.cfg == nil {
		return config.FeishuConnectConfig{}, infraerrors.ServiceUnavailable("CONFIG_NOT_READY", "config not loaded")
	}
	if !h.cfg.Feishu.Enabled {
		return config.FeishuConnectConfig{}, infraerrors.NotFound("OAUTH_DISABLED", "feishu oauth login is disabled")
	}
	return h.cfg.Feishu, nil
}

// feishuClient 构造或返回缓存的 client 实例（h-level 单例）。
// 若 cfg 关键字段与已缓存实例不一致，则重建，避免管理员改配置后旧凭据持续生效。
func (h *AuthHandler) feishuClient(cfg config.FeishuConnectConfig) *FeishuClient {
	h.feishuClientMu.Lock()
	defer h.feishuClientMu.Unlock()
	newCfg := feishuClientConfig{
		ClientID:     strings.TrimSpace(cfg.ClientID),
		ClientSecret: strings.TrimSpace(cfg.ClientSecret),
		TokenURL:     strings.TrimSpace(cfg.TokenURL),
		UserInfoURL:  strings.TrimSpace(cfg.UserInfoURL),
		RedirectURL:  strings.TrimSpace(cfg.RedirectURL),
	}
	if h.feishuClientInstance == nil || h.feishuClientInstance.cfg != newCfg {
		h.feishuClientInstance = &FeishuClient{
			cfg:        newCfg,
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}
	}
	return h.feishuClientInstance
}

// ─── Cookie helpers ────────────────────────────────────────────────────────

func setFeishuCookie(c *gin.Context, name string, value string, maxAgeSec int, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     feishuOAuthCookiePath,
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearFeishuCookie(c *gin.Context, name string, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     feishuOAuthCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ─── FeishuOAuthStart ──────────────────────────────────────────────────────

// FeishuOAuthStart 启动飞书 OAuth 登录流程。
// GET /api/v1/auth/oauth/feishu/start?redirect=/dashboard&intent=login
func (h *AuthHandler) FeishuOAuthStart(c *gin.Context) {
	if !h.requireActionCaptchaForOAuthLoginStart(c) {
		return
	}
	cfg, err := h.getFeishuOAuthConfig(c.Request.Context())
	if err != nil {
		redirectOAuthError(c, feishuOAuthDefaultFrontendCB, "feishu_not_enabled", "", "")
		return
	}

	state, err := oauth.GenerateState()
	if err != nil {
		response.ErrorFrom(c, infraerrors.InternalServer("OAUTH_STATE_GEN_FAILED", "failed to generate oauth state").WithCause(err))
		return
	}

	redirectTo := sanitizeFrontendRedirectPath(c.Query("redirect"))
	if redirectTo == "" {
		redirectTo = feishuOAuthDefaultRedirectTo
	}

	browserSessionKey, err := generateOAuthPendingBrowserSession()
	if err != nil {
		response.ErrorFrom(c, infraerrors.InternalServer("OAUTH_BROWSER_SESSION_GEN_FAILED", "failed to generate oauth browser session").WithCause(err))
		return
	}

	secureCookie := isRequestHTTPS(c)
	setFeishuCookie(c, feishuOAuthStateCookieName, encodeCookieValue(state), feishuOAuthCookieMaxAgeSec, secureCookie)
	setFeishuCookie(c, feishuOAuthRedirectCookie, encodeCookieValue(redirectTo), feishuOAuthCookieMaxAgeSec, secureCookie)

	intent := normalizeOAuthIntent(c.Query("intent"))
	setFeishuCookie(c, feishuOAuthIntentCookieName, encodeCookieValue(intent), feishuOAuthCookieMaxAgeSec, secureCookie)
	captureOAuthPromoCode(c, secureCookie)

	setOAuthPendingBrowserCookie(c, browserSessionKey, secureCookie)
	clearOAuthPendingSessionCookie(c, secureCookie)

	if intent == oauthIntentBindCurrentUser {
		bindCookieValue, err := h.buildOAuthBindUserCookieFromContext(c)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		setFeishuCookie(c, feishuOAuthBindUserCookieName, encodeCookieValue(bindCookieValue), feishuOAuthCookieMaxAgeSec, secureCookie)
	} else {
		clearFeishuCookie(c, feishuOAuthBindUserCookieName, secureCookie)
	}

	authURL, err := buildFeishuAuthorizeURL(cfg, state)
	if err != nil {
		response.ErrorFrom(c, infraerrors.InternalServer("OAUTH_BUILD_URL_FAILED", "failed to build feishu authorization url").WithCause(err))
		return
	}

	respondOAuthStart(c, authURL)
}

// buildFeishuAuthorizeURL 根据配置和 state 构建飞书授权 URL。
// 飞书 authen/v1/authorize 参数：client_id（App ID）、redirect_uri、response_type=code、state，scope 可选。
func buildFeishuAuthorizeURL(cfg config.FeishuConnectConfig, state string) (string, error) {
	base := strings.TrimSpace(cfg.AuthorizeURL)
	if base == "" {
		return "", infraerrors.InternalServer("FEISHU_AUTHORIZE_URL_EMPTY", "feishu authorize_url not configured")
	}
	redirectURI := strings.TrimSpace(cfg.RedirectURL)
	if redirectURI == "" {
		return "", infraerrors.InternalServer("FEISHU_REDIRECT_URL_EMPTY", "feishu redirect_url not configured")
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", infraerrors.InternalServer("FEISHU_AUTHORIZE_URL_PARSE_FAILED", "failed to parse feishu authorize_url").WithCause(err)
	}

	q := u.Query()
	q.Set("client_id", strings.TrimSpace(cfg.ClientID))
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)
	if scopes := strings.TrimSpace(cfg.Scopes); scopes != "" {
		q.Set("scope", scopes)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ─── FeishuOAuthCallback ───────────────────────────────────────────────────

// feishuUpstreamRedirect 在飞书上游调用失败时记录详细错误日志并跳错误页。
func feishuUpstreamRedirect(c *gin.Context, frontendCallback, step string, err error) {
	var apiErr *FeishuAPIError
	code := 0
	msg := ""
	httpStatus := 0
	if errors.As(err, &apiErr) {
		code = apiErr.Code
		msg = apiErr.Message
		httpStatus = apiErr.HTTP
	}
	slog.Error("feishu upstream call failed",
		"step", step,
		"feishu_code", code,
		"feishu_msg", msg,
		"http_status", httpStatus,
		"error", err.Error(),
	)
	if strings.TrimSpace(msg) == "" {
		msg = infraerrors.Message(err)
	}
	if code != 0 {
		msg = "feishu[" + itoa(code) + "] " + msg
	}
	redirectOAuthError(c, frontendCallback, "upstream_error", msg, "")
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// FeishuOAuthCallback 处理飞书授权回调。
// GET /api/v1/auth/oauth/feishu/callback?code=...&state=...
func (h *AuthHandler) FeishuOAuthCallback(c *gin.Context) {
	cfg, cfgErr := h.getFeishuOAuthConfig(c.Request.Context())
	if cfgErr != nil {
		response.ErrorFrom(c, cfgErr)
		return
	}

	frontendCallback := strings.TrimSpace(cfg.FrontendRedirectURL)
	if frontendCallback == "" {
		frontendCallback = feishuOAuthDefaultFrontendCB
	}

	if providerErr := strings.TrimSpace(c.Query("error")); providerErr != "" {
		redirectOAuthError(c, frontendCallback, "provider_error", providerErr, c.Query("error_description"))
		return
	}

	code := strings.TrimSpace(c.Query("code"))
	state := strings.TrimSpace(c.Query("state"))
	if code == "" || state == "" {
		redirectOAuthError(c, frontendCallback, "missing_params", "missing code/state", "")
		return
	}

	secureCookie := isRequestHTTPS(c)
	defer func() {
		clearFeishuCookie(c, feishuOAuthStateCookieName, secureCookie)
		clearFeishuCookie(c, feishuOAuthRedirectCookie, secureCookie)
		clearFeishuCookie(c, feishuOAuthIntentCookieName, secureCookie)
		clearOAuthPromoCodeCookie(c, secureCookie)
	}()

	expectedState, err := readCookieDecoded(c, feishuOAuthStateCookieName)
	if err != nil || state != expectedState {
		redirectOAuthError(c, frontendCallback, "csrf", "state mismatch", "")
		return
	}
	redirectTo, _ := readCookieDecoded(c, feishuOAuthRedirectCookie)
	intent, _ := readCookieDecoded(c, feishuOAuthIntentCookieName)
	intent = normalizeOAuthIntent(intent)
	browserSessionKey, _ := readOAuthPendingBrowserCookie(c)
	if strings.TrimSpace(browserSessionKey) == "" {
		redirectOAuthError(c, frontendCallback, "missing_browser_session", "missing browser session cookie", "")
		return
	}
	forceEmailOnSignup := h.isForceEmailOnThirdPartySignup(c.Request.Context())

	// ─── 两步链：code → user_access_token → user_info ───
	client := h.feishuClient(cfg)
	userToken, err := client.ExchangeCodeForUserToken(c.Request.Context(), code)
	if err != nil {
		feishuUpstreamRedirect(c, frontendCallback, "exchange_code", err)
		return
	}
	info, err := client.GetUserInfo(c.Request.Context(), userToken)
	if err != nil {
		feishuUpstreamRedirect(c, frontendCallback, "get_user_info", err)
		return
	}

	// 走到这里说明飞书已针对本应用的 client_id 给该用户签发了授权码，
	// 即用户在应用可见范围内；授权判定完全交给飞书应用本身（与 SigNoz 飞书 SSO 一致）。
	subject := info.Subject()
	identityKey := service.PendingAuthIdentityKey{ProviderType: feishuProviderType, ProviderKey: feishuProviderType, ProviderSubject: subject}
	email := strings.TrimSpace(strings.ToLower(info.PreferredEmail()))
	upstreamClaims := buildFeishuUpstreamClaims(info)

	// ─── 主动绑定分支 ───
	if intent == oauthIntentBindCurrentUser {
		targetUserID, err := h.readOAuthBindUserIDFromCookie(c, feishuOAuthBindUserCookieName)
		if err != nil {
			redirectOAuthError(c, frontendCallback, "invalid_state", "invalid bind user cookie", "")
			return
		}
		bindResolvedEmail := email
		if bindResolvedEmail == "" {
			bindResolvedEmail = buildFeishuSyntheticEmail(subject)
		}
		if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
			Intent: oauthIntentBindCurrentUser, Identity: identityKey,
			TargetUserID: &targetUserID, ResolvedEmail: bindResolvedEmail,
			RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
			UpstreamIdentityClaims: upstreamClaims,
			CompletionResponse:     map[string]any{"redirect": redirectTo},
		}); err != nil {
			redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
			return
		}
		clearFeishuCookie(c, feishuOAuthBindUserCookieName, secureCookie)
		redirectToFrontendCallback(c, frontendCallback)
		return
	}

	// ─── Level 1：auth_identities 命中 → 直接登录 ───
	if existing, _ := h.findOAuthIdentityUser(c.Request.Context(), identityKey); existing != nil {
		if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
			Intent: oauthIntentLogin, Identity: identityKey, TargetUserID: &existing.ID,
			ResolvedEmail: existing.Email, RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
			UpstreamIdentityClaims: upstreamClaims,
			CompletionResponse:     map[string]any{"redirect": redirectTo},
		}); err != nil {
			redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
			return
		}
		redirectToFrontendCallback(c, frontendCallback)
		return
	}

	signupBlocked := h.isFeishuSignupBlocked(c.Request.Context())

	// ─── 未命中且飞书没有返回邮箱 ───
	if email == "" {
		if signupBlocked {
			// 注册被拦 + 无邮箱可输：唯一出路是绑定已有账户
			if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
				Intent: oauthIntentLogin, Identity: identityKey, TargetUserID: nil,
				ResolvedEmail: "", RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
				UpstreamIdentityClaims: upstreamClaims,
				CompletionResponse:     feishuBindLoginCompletionResponse(redirectTo),
			}); err != nil {
				redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
				return
			}
			redirectToFrontendCallback(c, frontendCallback)
			return
		}
		if !cfg.RequireEmail && !forceEmailOnSignup {
			// 用稳定的 union_id/open_id 合成邮箱直接注册
			syntheticEmail := buildFeishuSyntheticEmail(subject)
			if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
				Intent: oauthIntentLogin, Identity: identityKey, TargetUserID: nil,
				ResolvedEmail: syntheticEmail, RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
				UpstreamIdentityClaims: upstreamClaims,
				CompletionResponse:     map[string]any{"redirect": redirectTo, "synthetic_email": syntheticEmail},
			}); err != nil {
				redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
				return
			}
			redirectToFrontendCallback(c, frontendCallback)
			return
		}
		// 需要邮箱：跳补邮箱页
		if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
			Intent: oauthIntentLogin, Identity: identityKey, TargetUserID: nil,
			ResolvedEmail: "", RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
			UpstreamIdentityClaims: upstreamClaims,
			CompletionResponse: map[string]any{
				"step":                      "email_completion",
				"requires_email_completion": true,
				"redirect":                  redirectTo,
			},
		}); err != nil {
			redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
			return
		}
		redirectToFrontendCallback(c, frontendCallback)
		return
	}

	// ─── 有邮箱：统一 choice pending session（可绑定同邮箱已有账户，或新建账户） ───
	compatEmailUser, _ := h.findFeishuCompatEmailUser(c.Request.Context(), email)
	if err := h.createFeishuOAuthChoicePendingSession(
		c, identityKey, email, redirectTo, browserSessionKey, upstreamClaims,
		compatEmailUser, forceEmailOnSignup, signupBlocked,
	); err != nil {
		redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
		return
	}
	redirectToFrontendCallback(c, frontendCallback)
}

func buildFeishuSyntheticEmail(subject string) string {
	return "feishu-" + strings.ToLower(strings.TrimSpace(subject)) + service.FeishuConnectSyntheticEmailDomain
}

// isFeishuSignupBlocked 当注册总开关关闭时返回 true（飞书没有企业模式豁免）。
func (h *AuthHandler) isFeishuSignupBlocked(ctx context.Context) bool {
	if h.settingSvc == nil {
		return false
	}
	return !h.settingSvc.IsRegistrationEnabled(ctx)
}

func feishuBindLoginCompletionResponse(redirectTo string) map[string]any {
	return map[string]any{
		"step":                      "bind_login_required",
		"existing_account_bindable": true,
		"create_account_allowed":    false,
		"redirect":                  redirectTo,
	}
}

// buildFeishuUpstreamClaims 把飞书用户信息整理成 pending session 的 upstream claims。
// suggested_display_name / suggested_avatar_url 供通用 pending 流程做"采用飞书资料"的确认。
func buildFeishuUpstreamClaims(info *FeishuUserInfo) map[string]any {
	if info == nil {
		info = &FeishuUserInfo{}
	}
	displayName := info.DisplayName()
	claims := map[string]any{
		"email":      info.PreferredEmail(),
		"username":   displayName,
		"nickname":   displayName,
		"subject":    info.Subject(),
		"open_id":    strings.TrimSpace(info.OpenID),
		"union_id":   strings.TrimSpace(info.UnionID),
		"user_id":    strings.TrimSpace(info.UserID),
		"tenant_key": strings.TrimSpace(info.TenantKey),
	}
	if displayName != "" {
		claims["suggested_display_name"] = displayName
	}
	if avatar := strings.TrimSpace(info.AvatarURL); avatar != "" {
		claims["suggested_avatar_url"] = avatar
	}
	return claims
}

// findFeishuCompatEmailUser 通过真实邮箱查找可与飞书账号兼容绑定的现有用户。
func (h *AuthHandler) findFeishuCompatEmailUser(ctx context.Context, email string) (*dbent.User, error) {
	client := h.entClient()
	if client == nil {
		return nil, infraerrors.ServiceUnavailable("PENDING_AUTH_NOT_READY", "pending auth service is not ready")
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || isThirdPartySyntheticEmail(email) {
		return nil, nil
	}

	userEntities, err := client.User.Query().
		Where(userNormalizedEmailPredicate(email)).
		Order(dbent.Asc(dbuser.FieldID)).
		All(ctx)
	if err != nil {
		return nil, infraerrors.InternalServer("COMPAT_EMAIL_LOOKUP_FAILED", "failed to look up compat email user").WithCause(err)
	}
	switch len(userEntities) {
	case 0:
		return nil, nil
	case 1:
		return userEntities[0], nil
	default:
		return nil, infraerrors.Conflict("USER_EMAIL_CONFLICT", "normalized email matched multiple users")
	}
}

// isThirdPartySyntheticEmail 判断邮箱是否为任一三方登录的合成邮箱。
func isThirdPartySyntheticEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	return strings.HasSuffix(email, service.FeishuConnectSyntheticEmailDomain) ||
		strings.HasSuffix(email, service.DingTalkConnectSyntheticEmailDomain) ||
		strings.HasSuffix(email, service.LinuxDoConnectSyntheticEmailDomain) ||
		strings.HasSuffix(email, service.OIDCConnectSyntheticEmailDomain) ||
		strings.HasSuffix(email, service.WeChatConnectSyntheticEmailDomain)
}

// createFeishuOAuthChoicePendingSession 创建飞书 OAuth 三方注册/绑定的 choice pending session。
// signupBlocked=true 时关闭"创建新账户"出口并直接进入 bind_login_required。
func (h *AuthHandler) createFeishuOAuthChoicePendingSession(
	c *gin.Context,
	identity service.PendingAuthIdentityKey,
	email string,
	redirectTo string,
	browserSessionKey string,
	upstreamClaims map[string]any,
	compatEmailUser *dbent.User,
	forceEmailOnSignup bool,
	signupBlocked bool,
) error {
	email = strings.TrimSpace(email)

	completionResponse := map[string]any{
		"step":                      oauthPendingChoiceStep,
		"adoption_required":         true,
		"redirect":                  strings.TrimSpace(redirectTo),
		"email":                     email,
		"resolved_email":            email,
		"existing_account_email":    "",
		"existing_account_bindable": false,
		"create_account_allowed":    !signupBlocked,
		"force_email_on_signup":     forceEmailOnSignup,
		"choice_reason":             "third_party_signup",
		"compat_email":              email,
	}
	resolvedChoiceEmail := email
	if compatEmailUser != nil {
		completionResponse["email"] = strings.TrimSpace(compatEmailUser.Email)
		completionResponse["existing_account_email"] = strings.TrimSpace(compatEmailUser.Email)
		completionResponse["existing_account_bindable"] = true
		completionResponse["choice_reason"] = "compat_email_match"
		resolvedChoiceEmail = strings.TrimSpace(compatEmailUser.Email)
	}
	if forceEmailOnSignup && compatEmailUser == nil {
		completionResponse["choice_reason"] = "force_email_on_signup"
	}
	if signupBlocked {
		completionResponse["step"] = "bind_login_required"
		completionResponse["existing_account_bindable"] = true
		completionResponse["choice_reason"] = "signup_blocked_redirect_to_bind"
	}

	var targetUserID *int64
	if compatEmailUser != nil && compatEmailUser.ID > 0 {
		targetUserID = &compatEmailUser.ID
	}

	return h.createOAuthPendingSession(c, oauthPendingSessionPayload{
		Intent:                 oauthIntentLogin,
		Identity:               identity,
		TargetUserID:           targetUserID,
		ResolvedEmail:          resolvedChoiceEmail,
		RedirectTo:             redirectTo,
		BrowserSessionKey:      browserSessionKey,
		UpstreamIdentityClaims: upstreamClaims,
		CompletionResponse:     completionResponse,
	})
}

// ─── Complete Registration ─────────────────────────────────────────────────

type completeFeishuOAuthRequest struct {
	InvitationCode   string `json:"invitation_code" binding:"required"`
	AffCode          string `json:"aff_code,omitempty"`
	AdoptDisplayName *bool  `json:"adopt_display_name,omitempty"`
	AdoptAvatar      *bool  `json:"adopt_avatar,omitempty"`
}

// CompleteFeishuOAuthRegistration 校验邀请码并完成飞书 OAuth 注册。
// POST /api/v1/auth/oauth/feishu/complete-registration
func (h *AuthHandler) CompleteFeishuOAuthRegistration(c *gin.Context) {
	var req completeFeishuOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	secureCookie := isRequestHTTPS(c)
	sessionToken, err := readOAuthPendingSessionCookie(c)
	if err != nil {
		clearOAuthPendingSessionCookie(c, secureCookie)
		clearOAuthPendingBrowserCookie(c, secureCookie)
		response.ErrorFrom(c, service.ErrPendingAuthSessionNotFound)
		return
	}
	browserSessionKey, err := readOAuthPendingBrowserCookie(c)
	if err != nil {
		clearOAuthPendingSessionCookie(c, secureCookie)
		clearOAuthPendingBrowserCookie(c, secureCookie)
		response.ErrorFrom(c, service.ErrPendingAuthBrowserMismatch)
		return
	}
	pendingSvc, err := h.pendingIdentityService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	session, err := pendingSvc.GetBrowserSession(c.Request.Context(), sessionToken, browserSessionKey)
	if err != nil {
		clearOAuthPendingSessionCookie(c, secureCookie)
		clearOAuthPendingBrowserCookie(c, secureCookie)
		response.ErrorFrom(c, err)
		return
	}
	if err := ensurePendingOAuthCompleteRegistrationSession(session); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if updatedSession, handled, err := h.legacyCompleteRegistrationSessionStatus(c, session); err != nil {
		response.ErrorFrom(c, err)
		return
	} else if handled {
		c.JSON(http.StatusOK, buildPendingOAuthSessionStatusPayload(updatedSession))
		return
	} else {
		session = updatedSession
	}
	if err := h.ensureBackendModeAllowsNewUserLogin(c.Request.Context()); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	email := strings.TrimSpace(session.ResolvedEmail)
	username := pendingSessionStringValue(session.UpstreamIdentityClaims, "username")
	if username == "" {
		if at := strings.Index(email, "@"); at > 0 {
			username = email[:at]
		} else {
			username = email
		}
	}
	if email == "" || username == "" {
		response.ErrorFrom(c, infraerrors.BadRequest("PENDING_AUTH_SESSION_INVALID", "pending auth registration context is invalid"))
		return
	}

	client := h.entClient()
	if client == nil {
		response.ErrorFrom(c, infraerrors.ServiceUnavailable("PENDING_AUTH_NOT_READY", "pending auth service is not ready"))
		return
	}
	if err := ensurePendingOAuthRegistrationIdentityAvailable(c.Request.Context(), client, session); err != nil {
		respondPendingOAuthBindingApplyError(c, err)
		return
	}
	decision, err := h.ensurePendingOAuthAdoptionDecision(c, session.ID, oauthAdoptionDecisionRequest{
		AdoptDisplayName: req.AdoptDisplayName,
		AdoptAvatar:      req.AdoptAvatar,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	tokenPair, user, err := h.authService.LoginOrRegisterOAuthWithTokenPairAndPromoCode(
		c.Request.Context(),
		email,
		username,
		req.InvitationCode,
		req.AffCode,
		pendingOAuthPromoCode(session),
		feishuProviderType,
	)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := applyPendingOAuthAdoptionAndConsumeSession(c.Request.Context(), client, h.authService, h.userService, session, decision, user.ID); err != nil {
		respondPendingOAuthBindingApplyError(c, err)
		return
	}
	h.authService.RecordSuccessfulLogin(c.Request.Context(), user.ID)
	clearOAuthPendingSessionCookie(c, secureCookie)
	clearOAuthPendingBrowserCookie(c, secureCookie)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
		"token_type":    "Bearer",
	})
}

// CreateFeishuOAuthAccount 从 pending 飞书 OAuth session 创建新账户。
// POST /api/v1/auth/oauth/feishu/create-account
func (h *AuthHandler) CreateFeishuOAuthAccount(c *gin.Context) {
	h.createPendingOAuthAccount(c, feishuProviderType)
}

// BindFeishuOAuthLogin 处理已有账户绑定飞书 OAuth 登录。
// POST /api/v1/auth/oauth/feishu/bind-login
func (h *AuthHandler) BindFeishuOAuthLogin(c *gin.Context) {
	h.bindPendingOAuthLogin(c, feishuProviderType)
}
