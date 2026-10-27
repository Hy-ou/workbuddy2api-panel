// fingerprint-probe — 定位上游 11-128 内容指纹的二分探针（P1 配套工具）。
//
// 背景：上游 console 域按**逐字精确匹配**拦截内容（HTTP 400 + code 11-128
// "Illegal API invocation from an unapproved channel"）。internal/upstream/sanitize.go
// 维护已知指纹词表；本工具用于**发现新指纹**：把客户端 system 文本切成块逐块试打
// 上游，命中的块递归细分到最小触发子串，产出可直接收进 sanitizeRewrites 的字符串。
//
// 用法：
//   go run ./cmd/fingerprint-probe -list                      # 列账号
//   go run ./cmd/fingerprint-probe -system-file sys.txt       # 整段试打一次
//   go run ./cmd/fingerprint-probe -system-file sys.txt -bisect   # 二分定位
//   go run ./cmd/fingerprint-probe -body-file dump.json -bisect   # 直接吃内容拦截落盘体
//
// 注意：
//   - 每次探测是一次真实上游调用（max_tokens=1），计入账号积分；
//   - 出站仍走 prepareBody（sanitize 默认开）：已知指纹已被改写，命中的只会是
//     **词表还没覆盖**的新指纹——这正是本工具要找的东西。需观察原始形态时用
//     -sanitize=false（此时已知指纹也会命中，注意区分）；
//   - 不走网关（不污染 degradeGate），直接打上游。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func main() {
	authDir := flag.String("auth-dir", "./auths", "凭证目录")
	uidPrefix := flag.String("uid", "", "账号 uid 前缀（空=取第一个 cn 账号）")
	model := flag.String("model", "deepseek-v4.1-flash", "裸模型名")
	systemText := flag.String("system", "", "system 文本（就地传入）")
	systemFile := flag.String("system-file", "", "system 文本文件")
	bodyFile := flag.String("body-file", "", "内容拦截落盘体（dump .json），提取其 system/developer 文本")
	userText := flag.String("user", "ping", "user 文本")
	sanitize := flag.Bool("sanitize", true, "出站指纹脱敏开关（默认开，与生产一致）")
	bisect := flag.Bool("bisect", false, "二分定位最小触发子串")
	maxProbes := flag.Int("max-probes", 80, "二分探针上限（防费用失控）")
	list := flag.Bool("list", false, "只列账号后退出")
	flag.Parse()

	accounts, err := auth.LoadDir(*authDir)
	if err != nil {
		fatal("load auths: %v", err)
	}
	if len(accounts) == 0 {
		fatal("no accounts in %s", *authDir)
	}
	if *list {
		for _, a := range accounts {
			fmt.Printf("%s  realm=%s  nick=%s  file=%s\n", a.UID, a.Realm(), a.Nickname, filepath.Base(a.FilePath))
		}
		return
	}

	acct := pick(accounts, *uidPrefix)
	if acct == nil {
		fatal("account not found for uid prefix %q", *uidPrefix)
	}

	client := upstream.New()
	client.SanitizeFingerprints.Store(*sanitize)
	p := &prober{client: client, acct: acct, model: *model, user: *userText, maxProbes: *maxProbes}

	text := *systemText
	if *systemFile != "" {
		raw, err := os.ReadFile(*systemFile)
		if err != nil {
			fatal("read system file: %v", err)
		}
		text = string(raw)
	}
	if *bodyFile != "" {
		raw, err := os.ReadFile(*bodyFile)
		if err != nil {
			fatal("read body file: %v", err)
		}
		text = systemTextFromDump(raw)
		if text == "" {
			fatal("no system/developer text in %s", *bodyFile)
		}
	}
	if strings.TrimSpace(text) == "" {
		fatal("no system text: pass -system / -system-file / -body-file")
	}

	fmt.Printf("account=%s realm=%s model=%s sanitize=%v system_bytes=%d\n",
		acct.UID, acct.Realm(), *model, *sanitize, len(text))

	if !*bisect {
		st, body, err := p.probe(text)
		fmt.Printf("status=%d err=%v\n%s\n", st, err, clip(body, 400))
		if st == 400 && strings.Contains(body, "11-128") {
			fmt.Println("=> 命中 11-128（加 -bisect 定位具体子串）")
		}
		return
	}

	if st, body, err := p.probe(text); err != nil || st == 0 {
		fatal("baseline probe failed: status=%d err=%v body=%s", st, err, body)
	} else if !isBlocked(st, body) {
		fmt.Println("=> 整段未被拦（无 11-128）：指纹不在这段文本里，或需与其它块组合")
		return
	}
	hits := p.minimize(text, 0)
	if len(hits) == 0 {
		fmt.Println("=> 块级二分未收敛：可能是块间组合触发，或每次调用间上游风控抖动。请重跑一次确认。")
		return
	}
	fmt.Printf("\n=== 最小触发子串 %d 条 ===\n", len(hits))
	for _, h := range hits {
		fmt.Printf("--- (%d bytes) ---\n%s\n", len(h), h)
	}
	fmt.Printf("\n探针总数=%d（上游调用上限 %d）\n", p.used, p.maxProbes)
	fmt.Println("下一步：把上面的字符串按「只改一个词、语义不变」的纪律收进 internal/upstream/sanitize.go 的 sanitizeRewrites，并在 sanitize_test.go 补回归用例。")
}

type prober struct {
	client    *upstream.Client
	acct      *auth.Auth
	model     string
	user      string
	maxProbes int
	used      int
}

// probe 单次试打：system 文本 + 固定 user 文本，max_tokens=1 非流式。
// 返回上游状态码与响应体原文。
func (p *prober) probe(system string) (int, string, error) {
	if p.used >= p.maxProbes {
		return 0, "", fmt.Errorf("probe budget exhausted (%d)", p.maxProbes)
	}
	p.used++
	msgs := make([]any, 0, 2)
	if strings.TrimSpace(system) != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": p.user})
	body, err := json.Marshal(map[string]any{
		"model":      p.model,
		"messages":   msgs,
		"max_tokens": 1,
		"stream":     false,
	})
	if err != nil {
		return 0, "", err
	}
	rc, status, respBody, err := p.client.ChatStream(p.acct, body, "", upstream.ChatMeta{})
	if rc != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<16))
		rc.Close()
	}
	if err != nil && status == 0 {
		return 0, "", err
	}
	return status, string(respBody), nil
}

func isBlocked(status int, body string) bool {
	return status == 400 && (strings.Contains(body, "11-128") ||
		strings.Contains(body, "unapproved channel") || strings.Contains(body, "illegal api invocation"))
}

// minimize 递归细分：块 → 行 → 句。返回最小触发子串（无法再细分的叶子）。
func (p *prober) minimize(text string, depth int) []string {
	if depth > 4 || p.used >= p.maxProbes {
		return nil
	}
	units := splitUnits(text, depth)
	if len(units) <= 1 {
		return nil
	}
	var hits []string
	for _, u := range units {
		if strings.TrimSpace(u) == "" {
			continue
		}
		st, body, err := p.probe(u)
		if err != nil {
			continue
		}
		if !isBlocked(st, body) {
			continue
		}
		if sub := p.minimize(u, depth+1); len(sub) > 0 {
			hits = append(hits, sub...)
			continue
		}
		hits = append(hits, strings.TrimSpace(u))
	}
	return hits
}

// splitUnits 按层级切分：0=空行分段，1=按行，2+=按句/子句。
func splitUnits(text string, depth int) []string {
	switch depth {
	case 0:
		return splitNonEmpty(text, "\n\n")
	case 1:
		return splitNonEmpty(text, "\n")
	default:
		out := splitNonEmpty(text, ". ")
		if len(out) > 1 {
			return out
		}
		return splitNonEmpty(text, ", ")
	}
}

func splitNonEmpty(text, sep string) []string {
	parts := strings.Split(text, sep)
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// systemTextFromDump 从内容拦截落盘体（见 internal/server/contentblock_dump.go）提取
// system/developer 消息文本，用空行拼接后交给二分。
func systemTextFromDump(raw []byte) string {
	var dump struct {
		OutboundBody json.RawMessage `json:"outbound_body"`
		Request      json.RawMessage `json:"request"`
	}
	body := raw
	if json.Unmarshal(raw, &dump) == nil {
		switch {
		case len(dump.OutboundBody) > 0 && string(dump.OutboundBody) != "null":
			body = dump.OutboundBody
		case len(dump.Request) > 0 && string(dump.Request) != "null":
			body = dump.Request
		}
	}
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		// 不是 JSON 请求体：原样当文本用
		return strings.TrimSpace(string(body))
	}
	var parts []string
	for _, m := range req.Messages {
		if m.Role != "system" && m.Role != "developer" {
			continue
		}
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			parts = append(parts, s)
			continue
		}
		var arr []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(m.Content, &arr) == nil {
			for _, part := range arr {
				if part.Type == "text" && part.Text != "" {
					parts = append(parts, part.Text)
				}
			}
		}
	}
	return strings.Join(parts, "\n\n")
}

func pick(accounts []*auth.Auth, prefix string) *auth.Auth {
	sorted := make([]*auth.Auth, len(accounts))
	copy(sorted, accounts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].UID < sorted[j].UID })
	for _, a := range sorted {
		if prefix == "" {
			if !a.IsGlobal() {
				return a
			}
			continue
		}
		if strings.HasPrefix(a.UID, prefix) {
			return a
		}
	}
	if prefix == "" {
		return sorted[0]
	}
	return nil
}

// clip 截断到 n 字节（只用于人类可读输出，不参与判定）。
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fingerprint-probe: "+format+"\n", args...)
	os.Exit(1)
}
