package main

import (
	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"proxy/internal/pkg/vunerabilities_scaner/handler"
	"proxy/internal/pkg/vunerabilities_scaner/repository"
	"proxy/internal/pkg/vunerabilities_scaner/usecase"
	"proxy/internal/pkg/lib"
	"log"
	"net/http"
	proxyHandler "proxy/internal/pkg/proxy_server/handler"
	proxyRepo "proxy/internal/pkg/proxy_server/repository"
)

type tomlConfig struct {
	Title string
	Web   webApi   `toml:"web-api"`
	Proxy proxyServer `toml:"proxy-server"`
	DB    database    `toml:"database"`
}

type webApi struct {
	Host string `toml:"host"`
	Port string
}

type proxyServer struct {
	Host string
	Port string
}

type database struct {
	DbName   string
	Username string
	Password string
	Host     string
	Port     string
}

func main() {
	var config tomlConfig
	_, err := toml.DecodeFile("./config.toml", &config);
	if  err != nil {
		log.Fatal(err)
	}

	db, err := lib.DBConnect(config.DB.Username, config.DB.DbName, config.DB.Password, config.DB.Host, config.DB.Port)
	if err != nil {
		log.Fatal(err)
	}

	newRepo := proxyRepo.NewRepoPostgres(db)
	proxyServer := proxyHandler.NewProxyServer(newRepo, ":"+config.Proxy.Port)
	go func() {
		log.Fatal(proxyServer.ListenAndServe())
	}()

	rRepo := repo.NewRepoPostgres(db)
	rUsecase := usecase.NewRepoUsecase(rRepo, proxyServer)
	handler := delivery.NewRepeaterHandler(rUsecase)

	muxRoute := mux.NewRouter()
	router := muxRoute.PathPrefix("/api/v1").Subrouter()
	{
		router.HandleFunc("/requests", handler.AllRequests).Methods(http.MethodGet)
		router.HandleFunc("/requests/{id}", handler.GetRequest).Methods(http.MethodGet)
		router.HandleFunc("/repeat/{id}", handler.RepeatRequest).Methods(http.MethodGet)
		router.HandleFunc("/scan/{id}", handler.Scan).Methods(http.MethodGet)
	}

	http.Handle("/", muxRoute)
	log.Print(http.ListenAndServe(":"+config.Web.Port, muxRoute))
}