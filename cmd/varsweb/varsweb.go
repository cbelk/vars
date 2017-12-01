package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/alexedwards/scs"
	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/julienschmidt/httprouter"
)

var (
	db             *sql.DB
	authenticate   func(string, string) (bool, error)
	sessionManager *scs.Manager
)

const webroot string = "/var/www/html"

func main() {
	// Read in the configurations
	ReadVarsConfig()
	ReadWebConfig()

	// Load the authentication plugin
	authenticate = LoadAuth()

	// Start the database connection
	db, err := varsapi.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}
	defer varsapi.CloseDB(db)

	// Create Session Manager
	sessionManager = scs.NewCookieManager(webConf.Skey)

	// Set paths
	router := httprouter.New()
	router.GET("/", LoginGet)
	router.POST("/", LoginPost)
	router.GET("/session", DisplaySession)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", webConf.Port), router))
}

// *** used for testing -- REMOVE ***
func DisplaySession(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var emp vars.Employee
	session := sessionManager.Load(r)
	authed, err := session.GetBool("authed")
	if err != nil {
		w.WriteHeader(500)
	}
	err = session.GetObject("employee", &emp)
	if err != nil {
		w.WriteHeader(500)
	}
	w.Write([]byte(fmt.Sprintf("authed: %v\nempObject: %v\n", authed, emp)))
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
	session := sessionManager.Load(r)
	if authed {
		emp, err := varsapi.GetEmployeeByUsername(u)
		if err != nil {
			w.WriteHeader(500)
		}
		err = session.PutBool(w, "authed", true)
		if err != nil {
			w.WriteHeader(500)
		}
		err = session.PutObject(w, "employee", emp)
		if err != nil {
			w.WriteHeader(500)
		}
		w.Write([]byte("Sucessful login"))
	} else {
		err = session.PutBool(w, "authed", false)
		if err != nil {
			w.WriteHeader(500)
		}
		var emp vars.Employee
		err = session.PutObject(w, "employee", emp)
		if err != nil {
			w.WriteHeader(500)
		}
		w.Write([]byte("Invalid credentials"))
	}
}
