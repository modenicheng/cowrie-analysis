// 报告归档目录轮转：按归档文件名内嵌日期删除超过保留期的 .json/.png，
// 由 e3-analyst daemon 启动时与每 24h 调用（reports.retention_days）。
package reports

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var (
	// yearDirRe / monthDirRe 界定归档目录的两层结构 YYYY/MM。
	yearDirRe  = regexp.MustCompile(`^\d{4}$`)
	monthDirRe = regexp.MustCompile(`^\d{2}$`)
	// archiveNameRe 匹配归档文件名 {daily|weekly}-YYYYMMDD.{json|png}；
	// 日期合法性由 time.Parse 兜底（如 20261301 解析失败即跳过）。
	archiveNameRe = regexp.MustCompile(`^(daily|weekly)-(\d{8})\.(json|png)$`)
)

// archiveDateLayout 是归档文件名中的紧凑日期格式（UTC 零点语义）。
const archiveDateLayout = "20060102"

// CleanupArchives 轮转报告归档目录 dir（YYYY/MM 两层结构）：
//
//   - retentionDays <= 0 → 禁用，直接返回 nil；
//   - 匹配 daily-YYYYMMDD.json/.png 与 weekly-YYYYMMDD.json/.png 的文件，
//     按文件名内嵌日期（解析为 UTC 零点）满足
//     fileDate+retentionDays*24h <= now.UTC() 即删除；
//   - 解析不了的文件名（含日期非法、其他命名）跳过不动；
//   - 变空的月/年目录顺手 os.Remove（best-effort，失败忽略——非空目录
//     的 Remove 必然失败，属正常路径）；
//   - dir 不存在视为无事可清，返回 nil。
func CleanupArchives(dir string, retentionDays int, now time.Time) error {
	if retentionDays <= 0 {
		return nil
	}
	now = now.UTC()
	yearEnts, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reports.CleanupArchives: 读取归档目录 %s 失败: %w", dir, err)
	}
	for _, ye := range yearEnts {
		if !ye.IsDir() || !yearDirRe.MatchString(ye.Name()) {
			continue
		}
		yearPath := filepath.Join(dir, ye.Name())
		monthEnts, err := os.ReadDir(yearPath)
		if err != nil {
			return fmt.Errorf("reports.CleanupArchives: 读取年目录 %s 失败: %w", yearPath, err)
		}
		for _, me := range monthEnts {
			if !me.IsDir() || !monthDirRe.MatchString(me.Name()) {
				continue
			}
			monthPath := filepath.Join(yearPath, me.Name())
			if err := cleanupArchiveMonth(monthPath, retentionDays, now); err != nil {
				return err
			}
			// 月目录已空则顺手移除；成功后再尝试移除已空的年目录
			// （best-effort，失败忽略）。
			if os.Remove(monthPath) == nil {
				_ = os.Remove(yearPath)
			}
		}
	}
	return nil
}

// cleanupArchiveMonth 删除单个 YYYY/MM 目录内超过保留期的归档文件；
// 文件删除失败返回错误（真实 IO 问题应上报），无关文件一律不动。
func cleanupArchiveMonth(monthPath string, retentionDays int, now time.Time) error {
	ents, err := os.ReadDir(monthPath)
	if err != nil {
		return fmt.Errorf("reports.CleanupArchives: 读取月目录 %s 失败: %w", monthPath, err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue // 月目录内的子目录不属归档命名，不递归
		}
		m := archiveNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue // 非归档命名：跳过不动
		}
		fileDate, perr := time.ParseInLocation(archiveDateLayout, m[2], time.UTC)
		if perr != nil {
			continue // 日期不合法：跳过不动
		}
		if fileDate.Add(time.Duration(retentionDays) * 24 * time.Hour).After(now) {
			continue // 未过保留期
		}
		if rerr := os.Remove(filepath.Join(monthPath, e.Name())); rerr != nil {
			return fmt.Errorf("reports.CleanupArchives: 删除过期归档 %s 失败: %w",
				filepath.Join(monthPath, e.Name()), rerr)
		}
	}
	return nil
}
