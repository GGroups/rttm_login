package comm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	USR "github.com/GGroups/rttm_login/user"
	log "github.com/cihub/seelog"
	"github.com/golang-jwt/jwt"
)

type RequestWarp struct {
	Usr    USR.Usr     `json:"user"`
	Resp   interface{} `json:"respObj"`
	Cookie http.Cookie `json:"cookie"`
}

var secret_bin_key = []byte("my_secret_key")

func init() {
	file, err := os.Open(GetDBLite())
	if err != nil {
		log.Error("#Load ", GetDBLite(), err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var outstr string
	for scanner.Scan() {
		outstr += strings.TrimSpace(scanner.Text())
	}
	secret_bin_key = []byte(outstr)
}

func DecodeRequestFilterUsr(c context.Context, request *http.Request) (interface{}, error) {
	if request.Method != "POST" {
		return nil, errors.New("#must POST")
	}
	u := USR.Usr{}
	errc, err := GetUserFromToken(request, &u)
	if err != nil {
		return nil, RepErr(errc, err)
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, RepErr(http.StatusBadRequest, err)
	}
	var obj USR.ReqUsers
	err = json.Unmarshal(body, &obj)
	if err != nil {
		return nil, RepErr(http.StatusBadRequest, err)
	}
	w := RequestWarp{Usr: u, Resp: obj}
	return w, nil
}

func GetUserFromToken(request *http.Request, usr *USR.Usr) (int, error) {
	c, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			return http.StatusUnauthorized, err
		}
		return http.StatusBadRequest, err
	}
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &USR.LoginClaim{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return secret_bin_key, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return http.StatusUnauthorized, err
		}
		return http.StatusBadRequest, err
	}
	if !tkn.Valid {
		return http.StatusUnauthorized, err
	}
	*usr = claims.UsrObj

	return http.StatusOK, nil
}

func GetTokenCookie(request *http.Request, t *http.Cookie) error {
	tn, err := request.Cookie("token")
	if err != nil {
		return err
	}
	*t = *tn
	return nil
}
