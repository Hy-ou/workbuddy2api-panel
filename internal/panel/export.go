package panel

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// accountExport 一键导出单个账号的凭证 JSON（与 auths/workbuddy-*.json 同构，
// 可直接放回 auths/ 目录或导入其他部署）。
//
//	GET /panel/api/accounts/{uid}/export
//
// 响应带 Content-Disposition: attachment，浏览器点击即落盘。文件含
// accessToken/refreshToken 明文，因此必须挂在 withAuth 之后，并显式禁止缓存，
// 避免凭证被浏览器/中间代理留存。
func (p *Panel) accountExport(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !validUID(uid) {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if p.cfg.Pool == nil {
		writeErr(w, http.StatusNotImplemented, "account pool not available")
		return
	}
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	raw, err := a.ExportJSON()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export: "+err.Error())
		return
	}
	filename := fmt.Sprintf("workbuddy-%s.json", uid)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	// 日志只记 UID，不落 token。
	log.Printf("panel: export uid=%s（凭证 JSON 已下载）", uid)
}

// accountsExport 批量导出全部账号凭证为单个 JSON 数组文件（元素与单账号导出
// 同构，可直接拆分为 auths/workbuddy-*.json）。
//
//	GET /panel/api/accounts/export
//
// 响应头 X-Exported-Count / X-Skipped-Count 告诉前端实际导出与跳过的账号数；
// 跳过的是凭证为空等无法导出的异常账号，不阻断其余账号。
func (p *Panel) accountsExport(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Pool == nil {
		writeErr(w, http.StatusNotImplemented, "account pool not available")
		return
	}
	statuses := p.cfg.Pool.List() // 按 UID 排序，导出顺序稳定
	docs := make([]map[string]any, 0, len(statuses))
	skipped := 0
	for _, st := range statuses {
		a := p.cfg.Pool.AuthByUID(st.UID)
		if a == nil {
			skipped++
			continue
		}
		doc, err := a.ExportDocument()
		if err != nil {
			skipped++
			log.Printf("panel: batch export skip uid=%s: %v", st.UID, err)
			continue
		}
		docs = append(docs, doc)
	}
	if len(docs) == 0 {
		writeErr(w, http.StatusNotFound, "no accounts to export")
		return
	}
	raw, err := json.MarshalIndent(docs, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export: "+err.Error())
		return
	}
	raw = append(raw, '\n')

	filename := fmt.Sprintf("workbuddy-accounts-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Exported-Count", strconv.Itoa(len(docs)))
	w.Header().Set("X-Skipped-Count", strconv.Itoa(skipped))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	log.Printf("panel: batch export %d account(s), skipped %d", len(docs), skipped)
}
