//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//    VARS (Vulnerability Analysis Reference System) is software used to track      //
//    vulnerabilities from discovery through analysis to mitigation.                //
//    Copyright (C) 2017  Christian Belk                                            //
//                                                                                  //
//    This program is free software: you can redistribute it and/or modify          //
//    it under the terms of the GNU General Public License as published by          //
//    the Free Software Foundation, either version 3 of the License, or             //
//    (at your option) any later version.                                           //
//                                                                                  //
//    This program is distributed in the hope that it will be useful,               //
//    but WITHOUT ANY WARRANTY; without even the implied warranty of                //
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                 //
//    GNU General Public License for more details.                                  //
//                                                                                  //
//    See the full License here: https://github.com/cbelk/vars/blob/master/LICENSE  //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/alexedwards/scs"
	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/julienschmidt/httprouter"
)

const (
	AdminUser      = 0
	PrivilegedUser = 1
	StandardUser   = 2
	Reporter       = 3
)

var (
	Conf           vars.Config
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
	var err error
	db, err = vars.ConnectDB(&Conf)
	if err != nil {
		log.Fatal(err)
	}
	defer vars.CloseDB(db)

	// Create Session Manager
	sessionManager = scs.NewCookieManager(webConf.Skey)
	//sessionManager.Secure(true)

	// Set paths
	router := httprouter.New()
	router.GET("/", handleIndex)
	router.GET("/login", handleLoginGet)
	router.POST("/login", handleLoginPost)
	router.GET("/logout", handleLogout)
	router.GET("/session", DisplaySession)
	router.GET("/vulnerability/:vuln", handleVulnerabilities)
	router.PUT("/vulnerability/:vuln/:field", handleVulnerabilityPut)
	router.POST("/vulnerability/:vuln/:field", handleVulnerabilityPost)
	router.POST("/vulnerability/:vuln/:field/:item", handleVulnerabilityPost)
	router.DELETE("/vulnerability/:vuln/:field/:item", handleVulnerabilityDelete)

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
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write([]byte(fmt.Sprintf("user object: %v\nis user authed: %v\nemployee object: %v", user, user.Authed, user.Emp)))
}

// handleIndex serves the main page.
func handleIndex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if user.Authed {
		w.Header().Add("Content-Type", "text/html")
		err := templates.Lookup("index").Execute(w, user)
		if err != nil {
			http.Error(w, "Error with templating", http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// handleLoginGet serves the login page.
func handleLoginGet(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if user.Authed {
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		w.Header().Add("Content-Type", "text/html")
		err := templates.Lookup("login").Execute(w, nil)
		if err != nil {
			http.Error(w, "Error with templating", http.StatusInternalServerError)
		}
	}
}

// handleLoginPost uses the Authenticate function of the auth plugin to validate the user credentials.
func handleLoginPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var user User
	u := r.FormValue("username")
	p := r.FormValue("password")
	authed, err := authenticate(u, p)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	user.Authed = authed
	session := sessionManager.Load(r)
	if user.Authed {
		emp, err := varsapi.GetEmployeeByUsername(u)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		user.Emp = emp
		err = session.PutObject(w, "user", user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		err = session.PutObject(w, "user", user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		err := templates.Lookup("login-failed").Execute(w, nil)
		if err != nil {
			http.Error(w, "Error with templating", http.StatusInternalServerError)
		}
	}
}

// handleLogout destroys the session and redirects to the login page.
func handleLogout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	session := sessionManager.Load(r)
	err := session.Destroy(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleVulnerabilities serves the vulnerability pages
func handleVulnerabilities(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	v := ps.ByName("vuln")
	if user.Authed {
		if user.Emp.Level <= StandardUser {
			if v == "all" {
				vulns, err := varsapi.GetVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				data := struct {
					U     *User
					Vulns []*vars.Vulnerability
				}{user, vulns}
				err = templates.Lookup("vulns").Execute(w, data)
				if err != nil {
					http.Error(w, "Error with templating", http.StatusInternalServerError)
				}
			} else if v == "open" {
				vulns, err := varsapi.GetOpenVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				data := struct {
					U     *User
					Vulns []*vars.Vulnerability
				}{user, vulns}
				err = templates.Lookup("vulns").Execute(w, data)
				if err != nil {
					http.Error(w, "Error with templating", http.StatusInternalServerError)
				}
			} else if v == "closed" {
				vulns, err := varsapi.GetClosedVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				data := struct {
					U     *User
					Vulns []*vars.Vulnerability
				}{user, vulns}
				err = templates.Lookup("vulns").Execute(w, data)
				if err != nil {
					http.Error(w, "Error with templating", http.StatusInternalServerError)
				}
			} else {
				vid, err := strconv.Atoi(v)
				if err != nil {
					err = templates.Lookup("page-not-exist").Execute(w, user)
					if err != nil {
						http.Error(w, "Error with templating", http.StatusInternalServerError)
					}
				}
				vuln, err := varsapi.GetVulnerability(int64(vid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = json.NewEncoder(w).Encode(vuln)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		} else {
			err := templates.Lookup("notauthorized-get").Execute(w, user)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleVulnerabilityPut(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	v := ps.ByName("vuln")
	vid, err := strconv.Atoi(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	field := ps.ByName("field")
	if user.Authed {
		switch field {
		case "cve":
			if user.Emp.Level <= StandardUser {
				cve := r.FormValue("cve")
				err := varsapi.AddCve(db, int64(vid), cve)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "ticket":
			if user.Emp.Level <= StandardUser {
				ticket := r.FormValue("ticket")
				err := varsapi.AddTicket(db, int64(vid), ticket)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleVulnerabilityDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	v := ps.ByName("vuln")
	vid, err := strconv.Atoi(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	field := ps.ByName("field")
	if user.Authed {
		switch field {
		case "cve":
			if user.Emp.Level <= StandardUser {
				cve := ps.ByName("item")
				err := varsapi.DeleteCve(db, int64(vid), cve)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "ticket":
			if user.Emp.Level <= StandardUser {
				ticket := ps.ByName("item")
				err := varsapi.DeleteTicket(db, int64(vid), ticket)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleVulnerabilityPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	v := ps.ByName("vuln")
	vid, err := strconv.Atoi(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	field := ps.ByName("field")
	if user.Authed {
		switch field {
		case "summary":
			if user.Emp.Level <= StandardUser {
				summ := r.FormValue("summary")
				err := varsapi.UpdateVulnerabilitySummary(db, int64(vid), summ)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "cve":
			if user.Emp.Level <= StandardUser {
				oldcve := ps.ByName("item")
				cve := r.FormValue("cve")
				err := varsapi.UpdateCve(db, int64(vid), oldcve, cve)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "cvss":
			if user.Emp.Level <= StandardUser {
				cvssScore := r.FormValue("cvssScore")
				cvssLink := r.FormValue("cvssLink")
				cScore, err := strconv.ParseFloat(cvssScore, 32)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					err := varsapi.UpdateCvss(db, int64(vid), float32(cScore), cvssLink)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "corpscore":
			if user.Emp.Level <= StandardUser {
				corpscore := r.FormValue("corpscore")
				cScore, err := strconv.ParseFloat(corpscore, 32)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					err := varsapi.UpdateCorpScore(db, int64(vid), float32(cScore))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "test":
			if user.Emp.Level <= StandardUser {
				test := r.FormValue("test")
				err := varsapi.UpdateVulnerabilityTest(db, int64(vid), test)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "mitigation":
			if user.Emp.Level <= StandardUser {
				mitigation := r.FormValue("mitigation")
				err := varsapi.UpdateVulnerabilityMitigation(db, int64(vid), mitigation)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "ticket":
			if user.Emp.Level <= StandardUser {
				oldticket := ps.ByName("item")
				ticket := r.FormValue("ticket")
				err := varsapi.UpdateTicket(db, int64(vid), oldticket, ticket)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
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
