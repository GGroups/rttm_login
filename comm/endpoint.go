package comm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	UR "github.com/GGroups/rttm_login/user"
)

type EmptyReqRep struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Code   int    `json:"code"`
}

func OkBody() EmptyReqRep {
	return EmptyReqRep{Status: "ok"}
}

func ErrBody() EmptyReqRep {
	return EmptyReqRep{Status: "err"}
}

func RepErr(code int, e error) error {
	b := EmptyReqRep{Status: "err", Msg: e.Error(), Code: code}
	s, _ := json.Marshal(b)
	return errors.New(string(s))
}

func CommEncodeResponse(c context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func HasAccessRole(usr UR.Usr, role string) bool {
	roles := strings.Split(usr.Roles, ",")
	doit := false
	for _, r := range roles {
		if strings.TrimSpace(r) == role {
			doit = true
		}
	}
	return doit
}
