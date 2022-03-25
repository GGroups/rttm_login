package user

import (
	"context"
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
}

var okbody EmptyReqRep
var errbody EmptyReqRep

func init() {
	okbody = EmptyReqRep{Status: "ok"}
	errbody = EmptyReqRep{Status: "err"}
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
			return nil, errors.New(ERR_USR_PASS_EMPTY + `not "wx"`)
		}
		var usr Usr
		err = sv.Login(r.Name, r.Pass, &usr)
		if err != nil {
			return Usr{}, err
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
			return "", err
		} else {
			return old, nil
		}
	}
}

func MakeReloadLoginDataEndPoint(sv IUser) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		err = sv.ReloadLoginData()
		if err != nil {
			return "", err
		} else {
			return okbody, nil
		}
	}
}
