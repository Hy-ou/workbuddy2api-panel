package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPreflightWritableCleansProbe 正常目录：探针写成功后必须删掉，不留垃圾文件。
func TestPreflightWritableCleansProbe(t *testing.T) {
	dir := t.TempDir()
	preflightWritable("state", dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("probe file should be removed, got %v", entries)
	}
}

// TestPreflightWritableLogsOnFailure 不可写目录（把一个普通文件当目录传进去）：
// 只打 ERR、不 panic、不阻塞启动——磁盘写不进仍要能对外服务。
func TestPreflightWritableLogsOnFailure(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	preflightWritable("state", file) // 触发错误分支：不应 panic
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("existing file must be untouched: %v", err)
	}
}
