package panel

import (
	"strings"
	"testing"
)

// TestParseImportAccountsCockpitArray 原有 cockpit tools 扁平数组保持兼容。
func TestParseImportAccountsCockpitArray(t *testing.T) {
	raw := []byte(`[{"id":"c1","uid":"u-1","access_token":"at","refresh_token":"rt","expires_at":1753600000000,"domain":"www.codebuddy.cn","nickname":"n1"}]`)
	accounts, err := parseImportAccounts(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("len=%d want 1", len(accounts))
	}
	got := accounts[0]
	if got.UID != "u-1" || got.AccessToken != "at" || got.RefreshToken != "rt" ||
		got.ExpiresAt != 1753600000000 || got.Domain != "www.codebuddy.cn" {
		t.Errorf("cockpit account mismatch: %+v", got)
	}
}

// TestParseImportAccountsNestedSingle 面板单账号导出对象：嵌套形字段要映射到
// cockpit 结构，expiresAt 从秒折算为毫秒，realm/enterprise/device_token 不丢。
func TestParseImportAccountsNestedSingle(t *testing.T) {
	raw := []byte(`{
	  "auth": {"accessToken":"at","refreshToken":"rt","expiresAt":1753600000,"domain":"www.workbuddy.ai","realm":"global"},
	  "account": {"uid":"u-2","enterpriseId":"ent-1","nickname":"n2"},
	  "device_token": "dt-1"
	}`)
	accounts, err := parseImportAccounts(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("len=%d want 1", len(accounts))
	}
	got := accounts[0]
	if got.UID != "u-2" || got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Errorf("nested auth mismatch: %+v", got)
	}
	if got.ExpiresAt != 1753600000000 {
		t.Errorf("ExpiresAt=%d want 1753600000000 (seconds -> ms)", got.ExpiresAt)
	}
	if got.Domain != "www.workbuddy.ai" || got.Realm != "global" {
		t.Errorf("realm/domain mismatch: %+v", got)
	}
	if got.EnterpriseID != "ent-1" || got.DeviceToken != "dt-1" || got.Nickname != "n2" {
		t.Errorf("account fields mismatch: %+v", got)
	}
}

// TestParseImportAccountsNestedArray 面板批量导出数组：顺序与字段都要保留。
func TestParseImportAccountsNestedArray(t *testing.T) {
	raw := []byte(`[
	  {"auth":{"accessToken":"at-1","refreshToken":"rt-1","expiresAt":1753600000,"domain":"www.codebuddy.cn","realm":"cn"},"account":{"uid":"u-1","nickname":"n1"}},
	  {"auth":{"accessToken":"at-2","refreshToken":"rt-2","expiresAt":1753600001,"domain":"www.workbuddy.ai","realm":"global"},"account":{"uid":"u-2","nickname":"n2"}}
	]`)
	accounts, err := parseImportAccounts(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("len=%d want 2", len(accounts))
	}
	if accounts[0].UID != "u-1" || accounts[0].Realm != "cn" || accounts[0].ExpiresAt != 1753600000000 {
		t.Errorf("first account mismatch: %+v", accounts[0])
	}
	if accounts[1].UID != "u-2" || accounts[1].Realm != "global" || accounts[1].ExpiresAt != 1753600001000 {
		t.Errorf("second account mismatch: %+v", accounts[1])
	}
}

// TestParseImportAccountsSingleFlat 扁平单对象也应接受（部分工具导出单条）。
func TestParseImportAccountsSingleFlat(t *testing.T) {
	raw := []byte(`{"uid":"u-1","access_token":"at","refresh_token":"rt","expires_at":1753600000000}`)
	accounts, err := parseImportAccounts(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(accounts) != 1 || accounts[0].UID != "u-1" {
		t.Fatalf("accounts=%+v", accounts)
	}
}

// TestParseImportAccountsInvalid 空文件、空数组、非法 JSON 都要给出可读错误。
func TestParseImportAccountsInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "   ", "empty file"},
		{"empty array", "[]", "empty accounts array"},
		{"bad json", "{not json", "invalid json"},
		{"scalar", "42", "expected a JSON object or array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseImportAccounts([]byte(c.raw))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err=%v want contains %q", err, c.want)
			}
		})
	}
}

// TestNestedAuthDocsToCockpitKeepsMilliseconds 已是毫秒的嵌套文件不重复乘 1000。
func TestNestedAuthDocsToCockpitKeepsMilliseconds(t *testing.T) {
	doc := nestedAuthDoc{}
	doc.Auth.ExpiresAt = 1753600000000
	doc.Account.UID = "u-1"
	out := nestedAuthDocsToCockpit([]nestedAuthDoc{doc})
	if len(out) != 1 || out[0].ExpiresAt != 1753600000000 {
		t.Fatalf("out=%+v", out)
	}
}
