package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// contentBlockBody 上游 11-128 内容拦截的典型信封（含 requestId，供落盘体取对账 id）。
const contentBlockBody = `{"code":11-128,"msg":"Illegal API invocation from an unapproved channel",` +
	`"requestId":"33e05bc5e08379c7019b21901c78c32d",` +
	`"displayMsg":{"en":"Request blocked. Please send it again","zh":"请求被拦截"}}`

// postChat 构造一次 chat 请求（测试内统一入口，省得每处重复 httptest 三连）。
func postChat(h *Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	return rec
}

// TestContentBlockDumpWritesBody 内容拦截时把出站请求体 + 上游响应体落盘：
// 首次（未降级）那份保留客户端原始 system——这是 fingerprint-probe 定位未知
// 指纹的唯一输入，缺了它 sanitize 词表只能靠猜。
func TestContentBlockDumpWritesBody(t *testing.T) {
	dir := t.TempDir()
	var calls int
	up := &upstream.Client{
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: 400,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(contentBlockBody)),
				}, nil
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(sseOK)),
			}, nil
		})},
		ChatBaseCN: "https://fake.example",
	}
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	h := NewHandler(Config{
		Pool:                p,
		Upstream:            up,
		PromptMode:          "passthrough",
		ContentBlockDumpDir: dir,
	})

	rec := postChat(h, `{"model":"glm-5.2","stream":true,"messages":[{"role":"system","content":"嫌疑指纹ABC"},{"role":"user","content":"hi"}]}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d want 200 after degraded retry (body=%s)", rec.Code, rec.Body)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("want 1 dump file in %s (err=%v)", dir, err)
	}
	if len(files) != 1 {
		t.Fatalf("want exactly the first-attempt dump, got %d: %v", len(files), files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read dump: %v", err)
	}
	var dump contentBlockDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatalf("dump is not valid JSON: %v (raw=%s)", err, raw)
	}
	// 首次出站体必须含客户端原始 system（降级后的第二次不含——那份没诊断价值）。
	if !strings.Contains(string(dump.OutboundBody), "嫌疑指纹ABC") {
		t.Errorf("outbound_body should carry the original system text: %s", dump.OutboundBody)
	}
	if dump.DegradedApplied {
		t.Error("first-attempt dump must not be flagged as degraded")
	}
	if dump.UpstreamStatus != 400 {
		t.Errorf("upstream_status=%d want 400", dump.UpstreamStatus)
	}
	if dump.UpstreamReqID != "33e05bc5e08379c7019b21901c78c32d" {
		t.Errorf("upstream_request_id=%q want parsed requestId", dump.UpstreamReqID)
	}
	if dump.UID != "u1" {
		t.Errorf("uid=%q want u1", dump.UID)
	}
	if dump.PromptMode != "passthrough" {
		t.Errorf("prompt_mode=%q", dump.PromptMode)
	}
	if dump.OutboundBytes == 0 || dump.Truncated {
		t.Errorf("outbound_bytes=%d truncated=%v", dump.OutboundBytes, dump.Truncated)
	}
	if !strings.Contains(dump.UpstreamBody, "11-128") {
		t.Errorf("upstream_body should carry the raw envelope: %q", dump.UpstreamBody)
	}
}

// TestContentBlockDumpDisabled 目录为空 = 关闭：不落盘，请求处理不受影响。
func TestContentBlockDumpDisabled(t *testing.T) {
	up := newFakeUpstream(t, func(authz string) (int, string, bool) {
		return 400, contentBlockBody, false
	})
	p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	h := NewHandler(Config{Pool: p, Upstream: up, PromptMode: "custom", PromptText: "SYS"})

	rec := postChat(h, `{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != 400 {
		t.Fatalf("code=%d want 400 content_blocked", rec.Code)
	}
}

// TestContentBlockDumpTruncatesOversize 超上限按 rune 边界截断并置 truncated，
// 落盘体仍是合法 JSON（截在中文字符中间会让整份文件不可解析）。
func TestContentBlockDumpTruncatesOversize(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{cfg: Config{ContentBlockDumpDir: dir, ContentBlockDumpMaxBytes: 64, ContentBlockDumpKeep: 5}}
	body := []byte(`{"model":"m","messages":[{"role":"system","content":"` + strings.Repeat("中", 200) + `"}]}`)
	h.dumpContentBlock(&auth.Auth{UID: "u1", AccessToken: "at"}, "m", "req-1", false, body, []byte(contentBlockBody), 400)

	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("want 1 dump file, got %v", files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var dump contentBlockDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatalf("truncated dump must stay valid JSON: %v", err)
	}
	if !dump.Truncated {
		t.Error("truncated flag should be set")
	}
	if dump.OutboundBytes != len(body) {
		t.Errorf("outbound_bytes=%d want %d (record the real size)", dump.OutboundBytes, len(body))
	}
}

// TestPruneContentBlockDumps 只保留最近 keep 份（按 mtime），磁盘不无界增长。
func TestPruneContentBlockDumps(t *testing.T) {
	dir := t.TempDir()
	names := []string{"a.json", "b.json", "c.json", "d.json"}
	for _, name := range names {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	// 拉开 mtime，让排序稳定（a 最旧）。
	base := time.Now().Add(-time.Hour)
	for i, name := range names {
		ts := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filepath.Join(dir, name), ts, ts); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	pruneContentBlockDumps(dir, 2)
	left, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(left) != 2 {
		t.Fatalf("want 2 kept, got %v", left)
	}
	for _, p := range left {
		n := filepath.Base(p)
		if n == "a.json" || n == "b.json" {
			t.Errorf("oldest dump %s should be pruned, kept=%v", n, left)
		}
	}
}
