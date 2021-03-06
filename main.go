package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	COMM "github.com/GGroups/rttm_login/comm"
	USR "github.com/GGroups/rttm_login/user"
	log "github.com/cihub/seelog"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func buildDB() error {
	db, err := sqlx.Open(USR.LITE3, USR.DB_FILE)
	if err != nil {
		return err
	}
	_, err = db.Exec(USR.SQL_CRE_USER)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		fmt.Printf("##ok:%v\n", err)
	} else if err != nil {
		return err
	}
	_, err = db.Exec(USR.SQL_CRE_ROLE)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		fmt.Printf("##ok:%v\n", err)
	} else if err != nil {
		return err
	}

	db.Close()

	return nil
}

func creatTestUser(usr *USR.Usr) error {
	db, err := sqlx.Open(USR.LITE3, USR.DB_FILE)
	if err != nil {
		return err
	}
	u := *usr
	_, err = db.Exec(USR.SQL_INS_USR, u.Id, u.Name, u.Pass, u.Roles)
	if err != nil {
		return err
	}
	db.Close()
	return nil
}

func creatTestRole(role *USR.Role) error {
	db, err := sqlx.Open(USR.LITE3, USR.DB_FILE)
	if err != nil {
		return err
	}
	r := *role
	_, err = db.Exec(USR.SQL_INS_ROLE, r.Id, r.Name)
	if err != nil {
		return err
	}
	db.Close()
	return nil
}

func main() {
	log.Info("#->Login service started!")

	err := buildDB()
	if err != nil {
		log.Error("#BuildDB:", err.Error())
	}
	creatTestUser(&USR.Usr{Id: 100, Name: "liq", Pass: "liq2022", Roles: "0101,1001,1002,"})
	creatTestUser(&USR.Usr{Id: 101, Name: "guou", Pass: "123321", Roles: "0101,1001,1002,8001,"})
	creatTestUser(&USR.Usr{Id: 102, Name: "litz", Pass: "litz2022", Roles: "0101,"})
	creatTestRole(&USR.Role{Id: 1, Name: "添加数据字典"})
	creatTestRole(&USR.Role{Id: 2, Name: "建表铺底语句"})
	creatTestRole(&USR.Role{Id: 3, Name: "导出"})

	us := USR.Usr{}
	err = us.ReloadLoginData()
	if err != nil {
		log.Error("#ReloadLoginData->", err.Error())
	}
	ep1 := USR.MakeLoginEndPoint(us)
	ep2 := USR.MakeLoginRefEndPoint(us)
	ep3 := USR.MakeReloadLoginDataEndPoint(us)
	ep4 := COMM.MakeEndPointFilterUsr(us)

	svr1 := httpTransport.NewServer(ep1, USR.LoginDecodeRequest, USR.LoginEncodeResponse)
	svr2 := httpTransport.NewServer(ep2, USR.LoginRefDecodeRequest, USR.LoginRefEncodeResponse)
	svr3 := httpTransport.NewServer(ep3, USR.ReLoadLoginDataDecodeRequest, USR.CommEncodeResponse)
	svr4 := httpTransport.NewServer(ep4, COMM.DecodeRequestFilterUsr, USR.CommEncodeResponse)

	routeSvr := mux.NewRouter()

	routeSvr.Handle(`/rttm/login/Login`, svr1).Methods("POST")
	routeSvr.Handle(`/rttm/login/LoginRef`, svr2).Methods("POST")
	routeSvr.Handle(`/rttm/login/LoginReload`, svr3).Methods("POST")
	routeSvr.Handle(`/rttm/login/GetUsers`, svr4).Methods("POST")

	//main loop
	ch := make(chan error, 2)
	go func() {
		log.Info("0.0.0.0:18000", `/rttm/login/**`)
		ch <- http.ListenAndServeTLS("0.0.0.0:18000", "./cert.pem", "./key.pem", routeSvr)
	}()
	go func() {
		log.Info("##", "wait for exit sigint...")
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		ch <- fmt.Errorf("%s", <-c)
	}()

	log.Info("MainSvr Terminated", <-ch)
}
