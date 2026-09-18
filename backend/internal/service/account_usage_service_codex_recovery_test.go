package service

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type codexRecoveryRepo struct {
	stubOpenAIAccountRepo
	clearedIDs []int64
}

func (r *codexRecoveryRepo) ClearRateLimit(_ context.Context, id int64) error {
	r.clearedIDs = append(r.clearedIDs, id)
	return nil
}

// codexProbeHeaders 复刻线上 account 4 的探测响应头：primary 为 7d 窗口，secondary 窗口为 0。
func codexProbeHeaders(used7d string) http.Header {
	headers := make(http.Header)
	headers.Set("x-codex-primary-used-percent", used7d)
	headers.Set("x-codex-primary-reset-after-seconds", "603863")
	headers.Set("x-codex-primary-window-minutes", "10080")
	headers.Set("x-codex-secondary-used-percent", "0")
	headers.Set("x-codex-secondary-reset-after-seconds", "0")
	headers.Set("x-codex-secondary-window-minutes", "0")
	return headers
}

func rateLimitedOpenAIAccount(id int64) *Account {
	limitedAt := time.Now().Add(-23 * time.Hour)
	resetAt := time.Now().Add(24 * time.Hour)
	return &Account{
		ID:               id,
		Platform:         PlatformOpenAI,
		Type:             AccountTypeOAuth,
		RateLimitedAt:    &limitedAt,
		RateLimitResetAt: &resetAt,
	}
}

// 上游周窗口提前重置后，探测成功且窗口未耗尽，必须清除本地遗留的限流，否则唯一账号会被继续挡到旧的 reset_at。
func TestAccountUsageService_ClearsStaleOpenAIRateLimitWhenProbeShowsRecovery(t *testing.T) {
	t.Parallel()

	repo := &codexRecoveryRepo{}
	svc := &AccountUsageService{accountRepo: repo}
	account := rateLimitedOpenAIAccount(4)

	svc.clearOpenAIRateLimitIfProbeRecovered(context.Background(), account, &http.Response{
		StatusCode: http.StatusOK,
		Header:     codexProbeHeaders("0"),
	})

	if len(repo.clearedIDs) != 1 || repo.clearedIDs[0] != 4 {
		t.Fatalf("ClearRateLimit calls = %v, want [4]", repo.clearedIDs)
	}
	if account.IsRateLimited() || account.RateLimitedAt != nil {
		t.Fatalf("account still rate limited in memory: limited_at=%v reset_at=%v", account.RateLimitedAt, account.RateLimitResetAt)
	}
}

func TestAccountUsageService_KeepsOpenAIRateLimitWhenProbeStillLimited(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		resp *http.Response
	}{
		{"429 with exhausted 7d window", &http.Response{StatusCode: http.StatusTooManyRequests, Header: codexProbeHeaders("100")}},
		{"429 without codex headers", &http.Response{StatusCode: http.StatusTooManyRequests, Header: make(http.Header)}},
		{"2xx but 7d window reports exhausted", &http.Response{StatusCode: http.StatusOK, Header: codexProbeHeaders("100")}},
		{"upstream 503", &http.Response{StatusCode: http.StatusServiceUnavailable, Header: codexProbeHeaders("0")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := &codexRecoveryRepo{}
			svc := &AccountUsageService{accountRepo: repo}
			account := rateLimitedOpenAIAccount(4)

			svc.clearOpenAIRateLimitIfProbeRecovered(context.Background(), account, tc.resp)

			if len(repo.clearedIDs) != 0 {
				t.Fatalf("ClearRateLimit calls = %v, want none", repo.clearedIDs)
			}
			if !account.IsRateLimited() {
				t.Fatal("account rate limit must be kept")
			}
		})
	}
}

func TestAccountUsageService_ProbeRecoverySkipsAccountsNotRateLimited(t *testing.T) {
	t.Parallel()

	repo := &codexRecoveryRepo{}
	svc := &AccountUsageService{accountRepo: repo}
	expired := time.Now().Add(-time.Minute)
	account := &Account{ID: 4, Platform: PlatformOpenAI, Type: AccountTypeOAuth, RateLimitResetAt: &expired}

	svc.clearOpenAIRateLimitIfProbeRecovered(context.Background(), account, &http.Response{
		StatusCode: http.StatusOK,
		Header:     codexProbeHeaders("0"),
	})

	if len(repo.clearedIDs) != 0 {
		t.Fatalf("ClearRateLimit calls = %v, want none for account without active rate limit", repo.clearedIDs)
	}
}
