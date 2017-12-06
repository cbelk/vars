package main

import (
	//"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	//"os"

	"github.com/alexedwards/scs"
	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/julienschmidt/httprouter"
)

var (
	db             *sql.DB
	sessionManager *scs.Manager
)

//const webroot string = "/var/www"

func main() {
	// Read in the configurations
	ReadVarsConfig()
	ReadWebConfig()

	// Load the authentication plugin
	//authenticate = LoadAuth()
	LoadAuth()

	// Load templates
	LoadTemplates()

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
	router.GET("/", handleLoginGet)
	router.POST("/", handleLoginPost)
	router.GET("/session", DisplaySession)

	// Serve css, javascript and images
	router.ServeFiles("/styles/*filepath", http.Dir(fmt.Sprintf("%s/styles", webConf.WebRoot)))
	router.ServeFiles("/scripts/*filepath", http.Dir(fmt.Sprintf("%s/scripts", webConf.WebRoot)))
	router.ServeFiles("/images/*filepath", http.Dir(fmt.Sprintf("%s/images", webConf.WebRoot)))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", webConf.Port), router))
}

// *** used for testing -- REMOVE ***
func DisplaySession(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	authed, emp, err := getSession(r)
	if err != nil {
		w.WriteHeader(500)
	}
	w.Write([]byte(fmt.Sprintf("authed: %v\nempObject: %v\n", authed, emp)))
}

// handleLoginGet serves the login page.
func handleLoginGet(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Add("Content-Type", "text/html")
	err := templates.Lookup("login").Execute(w, nil)
	if err != nil {
		http.Error(w, "Error with templating", http.StatusInternalServerError)
	}
}

// handleLoginPost uses the Authenticate function of the auth plugin to validate the user credentials.
func handleLoginPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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

// getSession unpacks the objects from the session cookie associated with the request and returns them.
func getSession(r *http.Request) (bool, *vars.Employee, error) {
	var emp vars.Employee
	session := sessionManager.Load(r)
	authed, err := session.GetBool("authed")
	if err != nil {
		return false, &emp, err
	}
	err = session.GetObject("employee", &emp)
	if err != nil {
		return authed, &emp, err
	}
	return authed, &emp, nil
}
