package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
)

// 内容拦截取证落盘（P1 配套，见 README「内容拦截误报与降级重试」）。
//
// 存在的理由：上游 console 域按**逐字精确匹配**拦截内容（HTTP 400 + code 11-128
// "Illegal API invocation from an unapproved channel"），而网关只能对**已知**指纹做
// 改写（internal/upstream/sanitize.go 的词表）。新指纹出现时，旧实现只留一行截断
// 200 字节的 WARN——既拿不到出站请求体，也就无从定位"到底是哪句话被拦"，
// sanitize 词表于是只能靠人工猜测扩充。
//
// 本落盘把命中的**出站请求体**（含 system/developer 原文）与上游响应体一起写进
// <state 同目录>/content-blocks/，配套工具 cmd/fingerprint-probe 直接吃这份文件做
// 二分定位（-body-file ... -bisect），产出可收进 sanitizeRewrites 的最小触发子串。
//
// 纪律：
//   - 只在 ErrContentBlocked 触发（罕见事件），不进入常规请求路径；
//   - 落盘失败只打一行 WARN，绝不影响请求本身的处理（错误路径不叠加错误）；
//   - 单文件上限 + 目录保留最近 N 个（GC），磁盘不会无界增长；
//   - 内容含用户提示词原文，目录与 state 文件同级（本地磁盘），README 明示该行为。
const (
	// defaultContentBlockDumpMaxBytes 单文件上限（缺省 8 MiB）。超限截断并置
	// truncated=true——截断体仍可做二分（上游只匹配单句指纹），但不保证完整。
	defaultContentBlockDumpMaxBytes = 8 << 20
	// defaultContentBlockDumpKeep 目录内保留的落盘体个数（缺省 20）。
	defaultContentBlockDumpKeep = 20
)

// contentBlockDump 一次内容拦截的取证记录。
//
// outbound_body 用 RawMessage 内嵌（JSON 合法时保留结构，探针可直接解析
// messages）；非法 JSON 时退化为字符串（畸形体同样要能取证）。
type contentBlockDump struct {
	Time            string          `json:"time"`
	Service         string          `json:"service"`
	Account         string          `json:"account"`
	UID             string          `json:"uid,omitempty"`
	Realm           string          `json:"realm,omitempty"`
	Model           string          `json:"model,omitempty"`
	PromptMode      string          `json:"prompt_mode,omitempty"`
	DegradedApplied bool            `json:"degraded_applied"`
	RequestID       string          `json:"request_id,omitempty"`
	UpstreamStatus  int             `json:"upstream_status"`
	UpstreamReqID   string          `json:"upstream_request_id,omitempty"`
	UpstreamBody    string          `json:"upstream_body"`
	OutboundBody    json.RawMessage `json:"outbound_body"`
	OutboundBytes   int             `json:"outbound_bytes"`
	Truncated       bool            `json:"truncated"`
}

// upstreamReqIDRe 上游错误信封里的 requestId（如 33e05bc5e08379c7019b21901c78c32d）。
// 单列一栏：向客户端/上游报障时它是唯一可对账的 id，埋在 body 里不好用。
var upstreamReqIDRe = regexp.MustCompile(`"requestId"\s*:\s*"([A-Za-z0-9_-]{8,64})"`)

// dumpContentBlock 把一次内容拦截的出站请求体与上游响应体落盘。
//
// body 是 handler 侧的出站请求体（降级重试后的第二次拦截则是 Rewrite(Degraded)
// 之后的那一份）；它未含 upstream.prepareBody 注入的 effort/prompt_cache_key，
// 但**新指纹在两侧都存在**（sanitize 只改写已知指纹），故足以供二分定位。
func (h *Handler) dumpContentBlock(acct *auth.Auth, model, requestID string, degraded bool, body, respBody []byte, status int) {
	dir := h.cfg.ContentBlockDumpDir
	if dir == "" || len(body) == 0 {
		return
	}
	maxBytes := h.cfg.ContentBlockDumpMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultContentBlockDumpMaxBytes
	}
	keep := h.cfg.ContentBlockDumpKeep
	if keep <= 0 {
		keep = defaultContentBlockDumpKeep
	}

	raw := body
	truncated := false
	if int64(len(raw)) > maxBytes {
		// 按 rune 边界截断：截在 UTF-8 中间字节会让落盘体变成非法 UTF-8。
		cut := int(maxBytes)
		for cut > 0 && (raw[cut]&0xC0) == 0x80 {
			cut--
		}
		raw = raw[:cut]
		truncated = true
	}

	rec := contentBlockDump{
		Time:            time.Now().Format(time.RFC3339),
		Service:         ServiceName,
		Account:         logAccount(acct),
		Model:           model,
		PromptMode:      h.cfg.PromptMode,
		DegradedApplied: degraded,
		RequestID:       requestID,
		UpstreamStatus:  status,
		UpstreamBody:    string(respBody),
		OutboundBytes:   len(body),
		Truncated:       truncated,
	}
	if acct != nil {
		rec.UID = acct.UID
		rec.Realm = acct.Realm()
	}
	if m := upstreamReqIDRe.FindSubmatch(respBody); m != nil {
		rec.UpstreamReqID = string(m[1])
	}
	if json.Valid(raw) {
		rec.OutboundBody = json.RawMessage(raw)
	} else {
		enc, err := json.Marshal(string(raw))
		if err != nil {
			return
		}
		rec.OutboundBody = json.RawMessage(enc)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("WARN: [server] content-block dump: marshal failed: %v", err)
		return
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("WARN: [server] content-block dump: mkdir %s: %v", dir, err)
		return
	}
	name := "content-block-" + time.Now().Format("20060102-150405") + "-" + dumpSuffix(rec.UpstreamReqID, raw) + ".json"
	path := filepath.Join(dir, name)
	// 临时文件 + rename：并发/断电只会留下完整文件或没有文件，不会留下半截 JSON
	//（半截 JSON 会让 fingerprint-probe -body-file 解析失败）。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("WARN: [server] content-block dump: write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("WARN: [server] content-block dump: rename %s: %v", path, err)
		_ = os.Remove(tmp)
		return
	}
	pruneContentBlockDumps(dir, keep)
	log.Printf("WARN: [server] content blocked: outbound body dumped to %s (%d bytes, realm=%s model=%s upstream_request_id=%s); locate the fingerprint with: go run ./cmd/fingerprint-probe -body-file %s -bisect",
		path, len(body), rec.Realm, model, orDash(rec.UpstreamReqID), path)
}

// dumpSuffix 文件名后缀：优先上游 requestId（可与上游对账），缺失时用 body 摘要，
// 保证同一请求的两次拦截（首次 + 降级重试）也不会互相覆盖。
func dumpSuffix(upstreamReqID string, body []byte) string {
	if upstreamReqID != "" {
		return upstreamReqID
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:6])
}

// pruneContentBlockDumps 只保留最近 keep 个落盘体（按 mtime 倒序），删除多余的。
// GC 失败不影响主流程（下次落盘再试）。
func pruneContentBlockDumps(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fileInfo struct {
		path string
		mod  time.Time
	}
	files := make([]fileInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{path: filepath.Join(dir, e.Name()), mod: info.ModTime()})
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for _, f := range files[keep:] {
		_ = os.Remove(f.path)
	}
}

// logAccount 账号显示标签：与日志行同一口径（logfmt.Label，昵称空时退 uid8）。
func logAccount(acct *auth.Auth) string {
	if acct == nil {
		return "-"
	}
	return logfmt.Label(acct.UID, acct.Nickname)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
