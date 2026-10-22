// Package migrations 内嵌数据库迁移脚本，按文件名前缀的版本号顺序应用。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
