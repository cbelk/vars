package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/alexedwards/scs"
	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/julienschmidt/httprouter"
)

var (
	db             *sql.DB
	sessionManager *scs.Manager
)

// User will hold whether the user is authed and their vars.Employee object.
type User struct {
	Authed bool
	Emp    *vars.Employee
}

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
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(500)
	}
	w.Write([]byte(fmt.Sprintf("user object: %v\nis user authed: %v\nemployee object: %v", user, user.Authed, user.Emp)))
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
	var user User
	u := r.FormValue("username")
	p := r.FormValue("password")
	authed, err := authenticate(u, p)
	if err != nil {
		w.WriteHeader(404)
	}
	user.Authed = authed
	session := sessionManager.Load(r)
	if user.Authed {
		emp, err := varsapi.GetEmployeeByUsername(u)
		if err != nil {
			w.WriteHeader(500)
		}
		user.Emp = emp
		err = session.PutObject(w, "user", user)
		if err != nil {
			w.WriteHeader(500)
		}
		http.Redirect(w, r, "/session", http.StatusFound)
	} else {
		err = session.PutObject(w, "user", user)
		if err != nil {
			w.WriteHeader(500)
		}
		err := templates.Lookup("login-failed").Execute(w, nil)
		if err != nil {
			http.Error(w, "Error with templating", http.StatusInternalServerError)
		}
	}
}

// getSession unpacks the objects from the session cookie associated with the request and returns them.
func getSession(r *http.Request) (*User, error) {
	var user User
	session := sessionManager.Load(r)
	err := session.GetObject("user", &user)
	if err != nil {
		return &user, err
	}
	return &user, nil
}
