package comm

const (
	META_TAG_TYPE_ERR  = "err"
	META_TAG_TYPE_HINT = "hint"
)

const (
	SECRET_KEY = `./key.bin`
	DB_FILE    = `./lite.db`
	LITE3      = "sqlite3"
)

const (
	_ = iota
	PROC_POS_source
	PROC_POS_create
	PROC_POS_insert
)

const (
	_ = iota
	ROLE_addtable
	ROLE_testsql
	ROLE_export
)

func GetRoleName(id int) string {
	switch id {
	case ROLE_addtable:
		return "添加数据字典"
	case ROLE_testsql:
		return "建表铺底语句"
	case ROLE_export:
		return "导出"
	default:
		return "未定义"
	}
}
