package user

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/logoove/sqlite"
)

const (
	TIME_5 = 5

	SECRET_KEY = `./key.bin`

	ERR_TIME_TOO_LONG  = `过期时间太长`
	ERR_DECODE_ERR     = `解码异常`
	ERR_TOKEN_LEN_ERR  = `token长度异常`
	ERR_USR_PASS_EMPTY = `用户名或密码为空`
	ERR_USR_PASS_ERR   = `用户名或密码错误`

	SQL_CRE_USER = `CREATE TABLE User ("uid" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  "name" char(200) NOT NULL, 
	  "pass" char(200) NOT NULL, 
	  "roles" char(100) NOT NULL);`

	SQL_SEL_USER = `SELECT uid, name, pass , roles FROM User; `

	SQL_CRE_ROLE = `CREATE TABLE Role ("uid" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" char(200) NOT NULL);`

	SQL_INS_USR = `insert into User (
	"uid",	"name", "pass", "roles") 
	 VALUES (?,?,?,?)`

	SQL_INS_ROLE = `insert into Role (
		"uid",	"name") 
		 VALUES (?,?)`

	DB_FILE = `./lite.db`

	LITE3 = "sqlite3"
)

type Usr struct {
	Id    int    `json:"uid" db:"uid"`
	Name  string `json:"name" db:"name"`
	Pass  string `json:"pass" db:"pass"`
	Roles string `json:"roles" db:"roles"`
}

type Role struct {
	Id   int    `json:"uid" db:"uid"`
	Name string `json:"name" db:"name"`
}

type IUser interface {
	Login(name string, pass string, usr *Usr) error
	LoginRef(token string) error
	ReloadLoginData() error
}

var jwt_bin_key = []byte("my_secret_key")
var users map[string]Usr

func (s Usr) Login(name string, pass string, usr *Usr) error {
	// Get the expected password from our in memory map
	findUsr, ok := users[name]

	// If a password exists for the given user
	if !ok || findUsr.Pass != pass {
		return errors.New(ERR_USR_PASS_ERR)
	} else {
		*usr = findUsr
	}

	return nil
}

func (s Usr) LoginRef(token string) error {
	if len(token) <= 10 {
		return errors.New(ERR_TOKEN_LEN_ERR)
	}
	return nil
}

func (s Usr) ReloadLoginData() error {
	//load key  SECRET_KEY
	file, err := os.Open(SECRET_KEY)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var outstr string
	for scanner.Scan() {
		outstr += strings.TrimSpace(scanner.Text())
	}
	jwt_bin_key = []byte(outstr)

	//load user to map
	db, err := sqlx.Open(LITE3, DB_FILE)
	if err != nil {
		return err
	}
	rows := []Usr{}
	err = db.Select(&rows, SQL_SEL_USER)
	if err != nil {
		return err
	}
	users = make(map[string]Usr)
	for _, u := range rows {
		users[u.Name] = u
	}

	db.Close()

	return nil
}
