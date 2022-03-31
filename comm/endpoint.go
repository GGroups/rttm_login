package comm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type EmptyReqRep struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func OkBody() EmptyReqRep {
	return EmptyReqRep{Status: "ok"}
}

func ErrBody() EmptyReqRep {
	return EmptyReqRep{Status: "err"}
}

func RepErr(e error) error {
	b := EmptyReqRep{Status: "err", Msg: e.Error()}
	s, _ := json.Marshal(b)
	return errors.New(string(s))
}

func CommEncodeResponse(c context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}
