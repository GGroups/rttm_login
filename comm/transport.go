package comm

import (
	"bufio"
	"net/http"
	"os"
	"strings"

	USR "github.com/GGroups/rttm_login/user"
	log "github.com/cihub/seelog"
	"github.com/golang-jwt/jwt"
)

type RequestWarp struct {
	Usr  USR.Usr     `json:"user"`
	Resp interface{} `json:"respObj"`
}

var secret_bin_key = []byte("my_secret_key")

func init() {
	file, err := os.Open(SECRET_KEY)
	if err != nil {
		log.Error("#Load ", SECRET_KEY, err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var outstr string
	for scanner.Scan() {
		outstr += strings.TrimSpace(scanner.Text())
	}
	secret_bin_key = []byte(outstr)
}

func GetUserFromToken(request *http.Request, usr *USR.Usr) error {
	c, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			//w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		//w.WriteHeader(http.StatusBadRequest)
		return err
	}
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &USR.LoginClaim{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return secret_bin_key, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			//w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		//w.WriteHeader(http.StatusBadRequest)
		return err
	}
	if !tkn.Valid {
		//w.WriteHeader(http.StatusUnauthorized)
		return err
	}
	*usr = claims.UsrObj

	return nil
}
