package user

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

func CommEncodeResponse(c context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func ReLoadLoginDataDecodeRequest(c context.Context, request *http.Request) (interface{}, error) {
	if request.Method != "POST" {
		return nil, errors.New("#must POST")
	}
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var obj EmptyReqRep
	err = json.Unmarshal(body, &obj)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func LoginDecodeRequest(c context.Context, request *http.Request) (interface{}, error) {
	if request.Method != "POST" {
		return nil, errors.New("#must POST")
	}
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var obj LoginRequest
	err = json.Unmarshal(body, &obj)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func LoginEncodeResponse(c context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")

	findUsr, errb := response.(Usr)
	if !errb {
		return errors.New(ERR_DECODE_ERR)
	}

	if len(findUsr.Name) <= 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return errors.New(ERR_USR_PASS_ERR)
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(TIME_5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &LoginClaim{
		UsrObj: findUsr,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err1 := token.SignedString(jwtKey)
	if err1 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err1
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return json.NewEncoder(w).Encode(okbody)
}

func LoginRefDecodeRequest(c context.Context, request *http.Request) (interface{}, error) {
	if request.Method != "POST" {
		return nil, errors.New("#must POST")
	}
	tokCok, err := request.Cookie("token")
	if err != nil {
		return "", err
	}
	return tokCok.Value, nil
}

func LoginRefEncodeResponse(c context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")

	tokStr, errb := response.(string)
	if errb {
		return errors.New(ERR_DECODE_ERR)
	}
	claims := &LoginClaim{}
	tkn, err := jwt.ParseWithClaims(tokStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return jwt.ErrSignatureInvalid
	}
	// (END) The code up-till this point is the same as the first part of the `Welcome` route

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Until(time.Unix(claims.ExpiresAt, 0)) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return errors.New(ERR_TIME_TOO_LONG)
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// Set the new token as the users `token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return json.NewEncoder(w).Encode(okbody)
}
