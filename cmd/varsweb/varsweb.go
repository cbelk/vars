package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/julienschmidt/httprouter"
)

var db *sql.DB
var authenticate func(string, string) (bool, error)

const webroot string = "/var/www/html"

func main() {
	// Read in the configurations
	ReadVarsConfig()
	ReadWebConfig()

	// Load the authentication plugin
	auth = LoadAuth()

	// Start the database connection
	db, err := varsapi.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}
	defer varsapi.CloseDB(db)

	// Set paths
	router := httprouter.New()
	router.GET("/", LoginGet)
	router.POST("/", LoginPost)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", webConf.Port), router))
}

// LoginGet serves the login page.
func LoginGet(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	file, err := os.Open(fmt.Sprintf("%s/login.html", webroot))
	if err != nil {
		w.WriteHeader(404)
	}
	defer file.Close()
	w.Header().Add("Content-Type", "text/html")
	br := bufio.NewReader(file)
	br.WriteTo(w)
}

// LoginPost uses the Authenticate function of the auth plugin to validate the user credentials.
func LoginPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	u := r.FormValue("username")
	p := r.FormValue("password")
	authed, err := authenticate(u, p)
	if err != nil {
		w.WriteHeader(404)
	}
	if authed {
		w.Write([]byte("Sucessful login"))
	} else {
		w.Write([]byte("Invalid credentials"))
	}
}
