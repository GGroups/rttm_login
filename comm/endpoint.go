package comm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	USR "github.com/GGroups/rttm_login/user"
	"github.com/go-kit/kit/endpoint"
)

type EmptyReqRep struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Code   int    `json:"code"`
}

func OkBody() EmptyReqRep {
	return EmptyReqRep{Status: "ok"}
}

func OkBodyM(msg string) EmptyReqRep {
	return EmptyReqRep{Status: "ok", Msg: msg}
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

func HasAccessRole(usr USR.Usr, role string) bool {
	roles := strings.Split(usr.Roles, ",")
	doit := false
	for _, r := range roles {
		if strings.TrimSpace(r) == role {
			doit = true
		}
	}
	return doit
}

func MakeEndPointFilterUsr(sv USR.IUser) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		w, ok := request.(RequestWarp)
		if !ok {
			return ErrBody(), RepErr(http.StatusBadRequest, errors.New("请求格式错误1"))
		}
		r, ok := (w.Resp).(USR.ReqUsers)
		if !ok {
			return ErrBody(), RepErr(http.StatusBadRequest, errors.New("请求格式错误2"))
		}

		var t []USR.Usr
		err = sv.GetUsersHasRoles(r.Roles, &t)
		if err != nil {
			return ErrBody(), RepErr(http.StatusBadRequest, err)
		} else {
			return t, nil
		}
	}
}
