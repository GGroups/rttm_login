package user

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/golang-jwt/jwt"
)

type LoginRequest struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

type EmptyReqRep struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

type DataRep struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}

type ReqUsers struct {
	Roles []string `json:"roles"`
}

func OkDataBody(d interface{}) DataRep {
	return DataRep{Status: "ok", Data: d}
}

func OkBody() EmptyReqRep {
	return EmptyReqRep{Status: "ok"}
}

func EpErr(e error) error {
	b := EmptyReqRep{Status: "err", Msg: e.Error()}
	s, _ := json.Marshal(b)
	return errors.New(string(s))
}

func RepErr(msg string) error {
	b := EmptyReqRep{Status: "err", Msg: msg}
	s, _ := json.Marshal(b)
	return errors.New(string(s))
}

type LoginClaim struct {
	UsrObj Usr `json:"usr"`
	jwt.StandardClaims
}

func MakeLoginEndPoint(sv IUser) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		r, ok := request.(LoginRequest)
		if !ok {
			return Usr{}, nil
		}
		r.Name = strings.TrimSpace(r.Name)
		r.Pass = strings.TrimSpace(r.Pass)
		if len(r.Name) <= 0 || len(r.Pass) <= 0 {
			return nil, RepErr(ERR_USR_PASS_EMPTY + `not "wx"`)
		}

		var usr Usr
		err = sv.Login(r.Name, r.Pass, &usr)
		if err != nil {
			return Usr{}, EpErr(err)
		} else {
			return usr, nil
		}
	}
}

func MakeLoginRefEndPoint(sv IUser) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		old, ok := request.(string)
		if !ok {
			return Usr{}, nil
		}

		err = sv.LoginRef(old)
		if err != nil {
			return "", EpErr(err)
		} else {
			return old, nil
		}
	}
}

func MakeReloadLoginDataEndPoint(sv IUser) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		err = sv.ReloadLoginData()
		if err != nil {
			return "", EpErr(err)
		} else {
			return OkBody(), nil
		}
	}
}
