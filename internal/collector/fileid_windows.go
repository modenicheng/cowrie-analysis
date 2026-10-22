//go:build windows

package collector

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openFileShared 以只读方式打开文件，共享模式必须包含 FILE_SHARE_DELETE：
// Go 的 os.Open 只请求 FILE_SHARE_READ|WRITE，会导致日志轮转方（rename）
// 或删除方收到 sharing violation。加 FILE_SHARE_DELETE 后他人可在采集器
// 持有句柄期间 rename/delete 该文件（POSIX 语义：已打开句柄仍可继续读）。
func openFileShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const share = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	h, err := windows.CreateFile(p, windows.GENERIC_READ, share, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// fileKey 返回打开文件的稳定标识 "vol:<卷序列号>:<文件索引>"。
// Windows 无法从路径 stat 得到文件索引，必须持有句柄调用
// GetFileInformationByHandle（NTFS 的 FileIndex 随文件终身稳定，
// 轮转改名不会变化；新创建的同名文件获得新索引），因此采集器全程持有
// 文件句柄并复用同一句柄读取。
func fileKey(f *os.File, _ os.FileInfo) (string, int64, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return "", 0, fmt.Errorf("fileid: 获取 %s 的原始连接失败: %w", f.Name(), err)
	}
	var handle windows.Handle
	if cerr := rc.Control(func(fd uintptr) { handle = windows.Handle(fd) }); cerr != nil {
		return "", 0, fmt.Errorf("fileid: 提取 %s 的句柄失败: %w", f.Name(), cerr)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", 0, fmt.Errorf("fileid: GetFileInformationByHandle(%s) 失败: %w", f.Name(), err)
	}
	index := (uint64(info.FileIndexHigh) << 32) | uint64(info.FileIndexLow)
	return fmt.Sprintf("vol:%d:%d", info.VolumeSerialNumber, index), int64(index), nil
}
