package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// cockpitAccount 映射 cockpit tools 导出格式的单个账号。
type cockpitAccount struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	UID            string `json:"uid"`
	Nickname       string `json:"nickname"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresAt      int64  `json:"expires_at"`
	Domain         string `json:"domain"`
	EnterpriseID   string `json:"enterprise_id"`
	DeviceToken    string `json:"device_token"`
	Realm          string `json:"realm"`
	DosageNotify   string `json:"dosage_notify_code"`
	PaymentType    string `json:"payment_type"`
	Status         string `json:"status"`
	UsageUpdatedAt int64  `json:"usage_updated_at"`
	LastCheckin    int64  `json:"last_checkin_time"`
	CheckinStreak  int    `json:"checkin_streak"`
	CreatedAt      int64  `json:"created_at"`
	LastUsed       int64  `json:"last_used"`
}

// nestedAuthDoc 面板「导出账号」的嵌套形凭证文档（与 auths/workbuddy-*.json 同构）。
// 导入时兼容单账号对象与批量数组两种形态，避免用户把面板导出文件再导回时被
// cockpit 扁平格式解析器误判成空字段。
type nestedAuthDoc struct {
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

// parseImportAccounts 解析账号导入文件，兼容三种形态：
//
//  1. cockpit tools 扁平数组：[{uid, access_token, refresh_token, expires_at(ms), ...}]
//  2. 面板单账号导出：{auth:{...}, account:{...}, device_token?}
//  3. 面板批量导出：[{auth:{...}, account:{...}}, ...]
//
// 面板导出的嵌套形统一折算成 cockpitAccount（expires_at 转毫秒），后续导入
// 流程（校验、落盘、签到/激活）完全复用，避免两套逻辑漂移。
func parseImportAccounts(raw []byte) ([]cockpitAccount, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("invalid json: %w", err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("empty accounts array")
		}
		if isNestedAuthDoc(items[0]) {
			var docs []nestedAuthDoc
			if err := json.Unmarshal(trimmed, &docs); err != nil {
				return nil, fmt.Errorf("invalid json: %w", err)
			}
			return nestedAuthDocsToCockpit(docs), nil
		}
		var accounts []cockpitAccount
		if err := json.Unmarshal(trimmed, &accounts); err != nil {
			return nil, fmt.Errorf("invalid json: %w", err)
		}
		return accounts, nil
	case '{':
		if isNestedAuthDoc(trimmed) {
			var doc nestedAuthDoc
			if err := json.Unmarshal(trimmed, &doc); err != nil {
				return nil, fmt.Errorf("invalid json: %w", err)
			}
			return nestedAuthDocsToCockpit([]nestedAuthDoc{doc}), nil
		}
		var acc cockpitAccount
		if err := json.Unmarshal(trimmed, &acc); err != nil {
			return nil, fmt.Errorf("invalid json: %w", err)
		}
		return []cockpitAccount{acc}, nil
	default:
		return nil, fmt.Errorf("invalid json: expected a JSON object or array")
	}
}

// isNestedAuthDoc 判断一个 JSON 对象是否为面板导出的嵌套形凭证文档。
// 只看 auth/account 键，避免把 cockpit 扁平对象误判；即便两者都缺，后续
// 仍会走扁平解析并按缺失字段逐条报错。
func isNestedAuthDoc(raw []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	_, hasAuth := probe["auth"]
	_, hasAccount := probe["account"]
	return hasAuth || hasAccount
}

// nestedAuthDocsToCockpit 把面板导出文档折算成导入路径的扁平账号结构。
// 面板导出的 expiresAt 是 Unix 秒；导入路径按 cockpit 的毫秒口径除以 1000，
// 因此这里统一乘 1000（已是毫秒的旧文件不重复放大）。
func nestedAuthDocsToCockpit(docs []nestedAuthDoc) []cockpitAccount {
	out := make([]cockpitAccount, 0, len(docs))
	for _, d := range docs {
		expiresAt := d.Auth.ExpiresAt
		if expiresAt > 0 && expiresAt < 1_000_000_000_000 {
			expiresAt *= 1000
		}
		out = append(out, cockpitAccount{
			UID:          d.Account.UID,
			Nickname:     d.Account.Nickname,
			AccessToken:  d.Auth.AccessToken,
			RefreshToken: d.Auth.RefreshToken,
			ExpiresAt:    expiresAt,
			Domain:       d.Auth.Domain,
			EnterpriseID: d.Account.EnterpriseID,
			DeviceToken:  d.DeviceToken,
			Realm:        d.Auth.Realm,
		})
	}
	return out
}

// importCockpit 接收账号 JSON 文件，批量导入账号到池中。
//
//	POST /panel/api/import/cockpit
//	Content-Type: multipart/form-data
//	Body: file=<json>
//
// 兼容 cockpit tools 扁平数组与面板自身导出的嵌套形（单账号对象 / 批量数组），
// 返回 {ok, total, imported, skipped, errors}。
func (p *Panel) importCockpit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "parse form: "+err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file field: "+err.Error())
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read file: "+err.Error())
		return
	}

	accounts, err := parseImportAccounts(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(accounts) == 0 {
		writeErr(w, http.StatusBadRequest, "empty accounts array")
		return
	}

	var total, imported, skipped int
	var errs []string

	for _, acc := range accounts {
		uid := strings.TrimSpace(acc.UID)
		at := strings.TrimSpace(acc.AccessToken)
		rt := strings.TrimSpace(acc.RefreshToken)
		if uid == "" || at == "" || rt == "" {
			skipped++
			errs = append(errs, fmt.Sprintf("missing required fields (id=%s)", acc.ID))
			continue
		}
		if !validImportUID(uid) {
			skipped++
			errs = append(errs, fmt.Sprintf("invalid uid (id=%s)", acc.ID))
			continue
		}

		// 显式 realm 优先（面板导出文件带 realm），否则按 domain 推断：
		// workbuddy.ai 家族 → global，其余 cn。
		realm := auth.ResolveRealm(acc.Realm, acc.Domain)

		// cockpit tools 的 expires_at 为毫秒时间戳，转为秒；面板导出的嵌套形
		// 在 nestedAuthDocsToCockpit 中已统一折算成毫秒，这里口径一致。
		expiresAt := acc.ExpiresAt / 1000
		if expiresAt <= 0 {
			expiresAt = time.Now().Add(365 * 24 * time.Hour).Unix()
		}

		nickname := acc.Nickname
		if strings.TrimSpace(nickname) == "" {
			nickname = acc.Email
		}

		a := &auth.Auth{
			AccessToken:  at,
			RefreshToken: rt,
			ExpiresAt:    expiresAt,
			Domain:       acc.Domain,
			UID:          uid,
			EnterpriseID: acc.EnterpriseID,
			Nickname:     nickname,
			DeviceToken:  acc.DeviceToken,
			FilePath:     filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", uid)),
		}

		if _, err := auth.BackfillRealmFor(a, realm); err != nil {
			skipped++
			errs = append(errs, fmt.Sprintf("uid=%s: set realm failed: %v", uid, err))
			continue
		}

		if err := a.SaveAtomic(); err != nil {
			skipped++
			errs = append(errs, fmt.Sprintf("uid=%s: save auth failed: %v", uid, err))
			continue
		}

		p.cfg.Pool.Add(a)
		p.cfg.Pool.Revive(uid)

		// 顺带签到/激活（幂等；失败仅记日志，不阻断导入）。
		if realm == "global" {
			if activated, err := p.cfg.Upstream.GlobalCompleteRegistration(a); err != nil {
				log.Printf("panel: import global 注册激活 uid=%s: %v", uid, err)
			} else if activated {
				log.Printf("panel: import global 注册激活 uid=%s 完成", uid)
			}
			if claimed, err := p.cfg.Upstream.ClaimTrial(a); err != nil {
				log.Printf("panel: import global trial uid=%s: %v", uid, err)
			} else if claimed {
				log.Printf("panel: import global trial uid=%s 已领", uid)
			}
		} else {
			if err := p.cfg.Upstream.DailyCheckin(a); err != nil {
				log.Printf("panel: import checkin uid=%s: %v", uid, err)
			}
		}
		if rm, tt, err := p.cfg.Upstream.UserResource(a); err == nil {
			p.cfg.Pool.ReenableIfCredits(uid, rm, tt)
		}

		imported++
	}

	total = len(accounts)
	log.Printf("panel: cockpit import finished total=%d imported=%d skipped=%d", total, imported, skipped)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"total":    total,
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

// validImportUID 校验导入 uid 是否可用于拼文件名（同 login.go validUID 口径）。
func validImportUID(uid string) bool {
	if uid == "" || len(uid) > 64 {
		return false
	}
	for _, c := range uid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
