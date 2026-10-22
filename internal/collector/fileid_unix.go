//go:build unix

package collector

import (
	"fmt"
	"os"
	"syscall"
)

// openFileShared 以只读方式打开文件。Unix 下 os.Open 本身不阻止他人
// rename/delete，无需特殊处理。
func openFileShared(path string) (*os.File, error) {
	return os.Open(path)
}

// fileKey 返回文件的稳定标识 "dev:<设备号>:<inode>"。
// rename 不改变 inode，轮转后同名新文件对应新 inode，因此 FileKey 能区分
// 轮转前后的两个文件（SPEC §6.2：不能仅用文件名做游标）。
// Unix 下可直接从 stat 结果取得，无需文件句柄。
func fileKey(_ *os.File, st os.FileInfo) (string, int64, error) {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", 0, fmt.Errorf("fileid: 非预期的 FileInfo 实现 %T（无法获取 dev/ino）", st.Sys())
	}
	return fmt.Sprintf("dev:%d:%d", uint64(stat.Dev), uint64(stat.Ino)), int64(stat.Ino), nil
}
