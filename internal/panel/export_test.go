package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// newExportTestPanel 构造带单账号的测试面板（Pool 内账号与磁盘 auth 文件同构）。
func newExportTestPanel(t *testing.T) (*Panel, *auth.Auth) {
	t.Helper()
	a := &auth.Auth{
		AccessToken:  "at-secret",
		RefreshToken: "rt-secret",
		ExpiresAt:    1753600000,
		Domain:       "www.codebuddy.cn",
		UID:          "u-1",
		EnterpriseID: "ent-1",
		Nickname:     "nick",
		DeviceToken:  "device-secret",
	}
	if _, err := auth.BackfillRealmFor(a, "cn"); err != nil {
		t.Fatalf("set realm: %v", err)
	}
	pl := pool.New("")
	t.Cleanup(pl.Close)
	pl.Add(a)
	return New(Config{Version: "test", APIKey: "test-key", Pool: pl}), a
}

// TestAccountExport 单账号导出：鉴权通过后返回附件 JSON，内容与 auth 文件同构，
// 且响应头禁止缓存（文件含 token 明文）。
func TestAccountExport(t *testing.T) {
	p, a := newExportTestPanel(t)

	req := httptest.NewRequest("GET", "/panel/api/accounts/"+a.UID+"/export", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type=%q want application/json", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); cd != `attachment; filename="workbuddy-u-1.json"` {
		t.Errorf("Content-Disposition=%q", cd)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", cc)
	}

	var doc struct {
		Auth struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
			Domain       string `json:"domain"`
			Realm        string `json:"realm"`
		} `json:"auth"`
		Account struct {
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
		} `json:"account"`
		DeviceToken string `json:"device_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("exported body is not json: %v\n%s", err, rr.Body.String())
	}
	if doc.Auth.AccessToken != "at-secret" || doc.Auth.RefreshToken != "rt-secret" ||
		doc.Auth.ExpiresAt != 1753600000 || doc.Auth.Domain != "www.codebuddy.cn" ||
		doc.Auth.Realm != "cn" {
		t.Errorf("auth fields mismatch: %+v", doc.Auth)
	}
	if doc.Account.UID != "u-1" || doc.Account.EnterpriseID != "ent-1" || doc.Account.Nickname != "nick" {
		t.Errorf("account fields mismatch: %+v", doc.Account)
	}
	if doc.DeviceToken != "device-secret" {
		t.Errorf("device_token = %q", doc.DeviceToken)
	}
}

// TestAccountsExport 批量导出：一个 JSON 数组，元素与单账号导出同构；响应头
// 回显导出/跳过数量；空凭证账号跳过但不阻断其余账号。
func TestAccountsExport(t *testing.T) {
	pl := pool.New("")
	t.Cleanup(pl.Close)
	for _, a := range []*auth.Auth{
		{AccessToken: "at-1", RefreshToken: "rt-1", ExpiresAt: 1753600000, Domain: "www.codebuddy.cn", UID: "u-1", Nickname: "n1"},
		{AccessToken: "at-2", RefreshToken: "rt-2", ExpiresAt: 1753600001, Domain: "www.workbuddy.ai", UID: "u-2", Nickname: "n2"},
		{UID: "u-bad"}, // 空凭证：批量导出应跳过
	} {
		if _, err := auth.BackfillRealmFor(a, auth.ResolveRealm("", a.Domain)); err != nil {
			t.Fatalf("set realm: %v", err)
		}
		pl.Add(a)
	}
	p := New(Config{Version: "test", APIKey: "test-key", Pool: pl})

	req := httptest.NewRequest("GET", "/panel/api/accounts/export", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type=%q want application/json", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "workbuddy-accounts-") || !strings.HasSuffix(cd, `.json"`) {
		t.Errorf("Content-Disposition=%q", cd)
	}
	if got := rr.Header().Get("X-Exported-Count"); got != "2" {
		t.Errorf("X-Exported-Count=%q want 2", got)
	}
	if got := rr.Header().Get("X-Skipped-Count"); got != "1" {
		t.Errorf("X-Skipped-Count=%q want 1", got)
	}

	var docs []struct {
		Auth struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			Realm        string `json:"realm"`
		} `json:"auth"`
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &docs); err != nil {
		t.Fatalf("batch body is not a json array: %v\n%s", err, rr.Body.String())
	}
	if len(docs) != 2 {
		t.Fatalf("len(docs)=%d want 2", len(docs))
	}
	if docs[0].Account.UID != "u-1" || docs[1].Account.UID != "u-2" {
		t.Errorf("batch order = %q, %q want u-1, u-2", docs[0].Account.UID, docs[1].Account.UID)
	}
	if docs[0].Auth.AccessToken != "at-1" || docs[1].Auth.RefreshToken != "rt-2" {
		t.Errorf("batch tokens mismatch: %+v", docs)
	}
	if docs[0].Auth.Realm != "cn" || docs[1].Auth.Realm != "global" {
		t.Errorf("batch realms = %q, %q", docs[0].Auth.Realm, docs[1].Auth.Realm)
	}
}

// TestAccountsExportEmptyPool 没有可导出账号时返回 404，而不是空数组文件。
func TestAccountsExportEmptyPool(t *testing.T) {
	pl := pool.New("")
	t.Cleanup(pl.Close)
	p := New(Config{Version: "test", APIKey: "test-key", Pool: pl})
	req := httptest.NewRequest("GET", "/panel/api/accounts/export", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d want 404 (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestAccountsExportAuth 批量导出同样必须走面板鉴权。
func TestAccountsExportAuth(t *testing.T) {
	p, _ := newExportTestPanel(t)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/panel/api/accounts/export", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: code=%d want 401", rr.Code)
	}
}

// TestAccountExportAuthAndNotFound 导出接口必须走面板鉴权；未知 UID 返回 404，
// 且错误响应不能泄露凭证。
func TestAccountExportAuthAndNotFound(t *testing.T) {
	p, _ := newExportTestPanel(t)

	// 无密钥 → 401。
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/panel/api/accounts/u-1/export", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: code=%d want 401", rr.Code)
	}

	// 未知账号 → 404。
	req := httptest.NewRequest("GET", "/panel/api/accounts/missing/export", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing account: code=%d want 404", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "at-secret") {
		t.Error("404 response must not leak tokens")
	}
}

// TestAccountExportInvalidUID 非法 UID（路径穿越形态）不得进入导出逻辑。
func TestAccountExportInvalidUID(t *testing.T) {
	p, _ := newExportTestPanel(t)
	req := httptest.NewRequest("GET", "/panel/api/accounts/..%2Fevil/export", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid uid: code=%d want 404/400 (body=%s)", rr.Code, rr.Body.String())
	}
}
