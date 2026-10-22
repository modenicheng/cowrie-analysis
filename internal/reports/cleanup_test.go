// CleanupArchives 表驱动测试：删旧留新、边界日期、0 禁用、无关文件不动、
// 非法日期跳过、变空月/年目录清理与非空目录保留。
package reports

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFileAt 在 root 下按相对路径写文件（自动建目录）。
func writeFileAt(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll %s 失败: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s 失败: %v", path, err)
	}
}

// exists 断言路径存在并返回是否。
func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("Stat %s 失败: %v", path, err)
	}
	return err == nil
}

func TestCleanupArchives(t *testing.T) {
	// 固定时钟：2026-10-22 00:00 UTC；retention=90 → 到期日 2026-07-24
	// （2026-07-24 + 90d = 2026-10-22 == now，边界当天删除）。
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

	t.Run("删旧留新并清理变空目录", func(t *testing.T) {
		root := t.TempDir()
		writeFileAt(t, root, "2025/09/daily-20250901.json", "old1")
		writeFileAt(t, root, "2025/09/weekly-20250915.png", "old2")
		writeFileAt(t, root, "2026/10/daily-20261021.json", "new1")
		writeFileAt(t, root, "2026/10/daily-20261021.png", "new2")

		if err := CleanupArchives(root, 90, now); err != nil {
			t.Fatalf("CleanupArchives 失败: %v", err)
		}
		for _, rel := range []string{
			"2025/09/daily-20250901.json", "2025/09/weekly-20250915.png",
		} {
			if exists(t, filepath.Join(root, filepath.FromSlash(rel))) {
				t.Errorf("过期文件 %s 未删除", rel)
			}
		}
		for _, rel := range []string{"2026/10/daily-20261021.json", "2026/10/daily-20261021.png"} {
			if !exists(t, filepath.Join(root, filepath.FromSlash(rel))) {
				t.Errorf("新文件 %s 不应删除", rel)
			}
		}
		// 2025/09 变空 → 月/年目录均被顺手移除。
		if exists(t, filepath.Join(root, "2025", "09")) {
			t.Error("变空月目录 2025/09 应被移除")
		}
		if exists(t, filepath.Join(root, "2025")) {
			t.Error("变空年目录 2025 应被移除")
		}
		if !exists(t, filepath.Join(root, "2026", "10")) {
			t.Error("未清空的月目录 2026/10 不应被移除")
		}
	})

	t.Run("边界日期当天删除次日保留", func(t *testing.T) {
		root := t.TempDir()
		writeFileAt(t, root, "2026/07/daily-20260724.json", "boundary") // 恰好到期
		writeFileAt(t, root, "2026/07/daily-20260725.png", "keep")      // 还差 1 天

		if err := CleanupArchives(root, 90, now); err != nil {
			t.Fatalf("CleanupArchives 失败: %v", err)
		}
		if exists(t, filepath.Join(root, "2026", "07", "daily-20260724.json")) {
			t.Error("边界日期（fileDate+90d == now）应删除")
		}
		if !exists(t, filepath.Join(root, "2026", "07", "daily-20260725.png")) {
			t.Error("次日文件（fileDate+90d > now）不应删除")
		}
	})

	t.Run("0 与负数禁用", func(t *testing.T) {
		root := t.TempDir()
		writeFileAt(t, root, "2020/01/daily-20200101.json", "very-old")

		for _, days := range []int{0, -1} {
			if err := CleanupArchives(root, days, now); err != nil {
				t.Fatalf("retentionDays=%d 应返回 nil, got %v", days, err)
			}
			if !exists(t, filepath.Join(root, "2020", "01", "daily-20200101.json")) {
				t.Fatalf("retentionDays=%d 不应删除任何文件", days)
			}
		}
	})

	t.Run("无关文件与非法日期不动", func(t *testing.T) {
		root := t.TempDir()
		keep := []string{
			"2025/01/daily-20250101.txt",    // 错误扩展名
			"2025/01/monthly-20250101.json", // 非 daily/weekly 前缀
			"2025/01/notes.json",            // 任意命名
			"2025/01/daily-20251301.json",   // 非法日期（13 月）
			"2025/01/daily-20250101.json",   // 合法但过期：应删除（对照组）
			"2025/daily-20250101.json",      // 不在月目录内：不动
			"daily-20250101.json",           // 直接在根下：不动
		}
		for _, rel := range keep {
			writeFileAt(t, root, rel, "x")
		}

		if err := CleanupArchives(root, 90, now); err != nil {
			t.Fatalf("CleanupArchives 失败: %v", err)
		}
		for _, rel := range keep {
			if rel == "2025/01/daily-20250101.json" {
				continue // 对照组：过期且合法 → 删除
			}
			if !exists(t, filepath.Join(root, filepath.FromSlash(rel))) {
				t.Errorf("无关文件 %s 不应被动", rel)
			}
		}
		if exists(t, filepath.Join(root, "2025", "01", "daily-20250101.json")) {
			t.Error("过期合法归档应被删除")
		}
		// notes.json 留在 2025/01 → 月目录不空，不应被移除。
		if !exists(t, filepath.Join(root, "2025", "01")) {
			t.Error("非空月目录不应被移除")
		}
	})

	t.Run("月目录含子目录不递归", func(t *testing.T) {
		root := t.TempDir()
		writeFileAt(t, root, "2025/01/daily-20250101.json", "old")
		writeFileAt(t, root, "2025/01/sub/daily-20250101.json", "nested")

		if err := CleanupArchives(root, 90, now); err != nil {
			t.Fatalf("CleanupArchives 失败: %v", err)
		}
		if exists(t, filepath.Join(root, "2025", "01", "daily-20250101.json")) {
			t.Error("月目录内的过期归档应被删除")
		}
		if !exists(t, filepath.Join(root, "2025", "01", "sub", "daily-20250101.json")) {
			t.Error("子目录内文件不递归处理")
		}
		// 2025/01 仍含 sub/ → 目录保留。
		if !exists(t, filepath.Join(root, "2025", "01")) {
			t.Error("含子目录的月目录不应被移除")
		}
	})

	t.Run("目录不存在返回nil", func(t *testing.T) {
		if err := CleanupArchives(filepath.Join(t.TempDir(), "nope", "reports"), 90, now); err != nil {
			t.Errorf("目录不存在应返回 nil, got %v", err)
		}
	})
}
