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
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

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
	router.PUT("/employee", handleEmployeeAdd)
	router.GET("/employee", handleEmployeePage)
	router.GET("/employee/:emp", handleEmployees)
	router.POST("/employee/:emp/:field", handleEmployeePost)
	router.GET("/notes/:vuln", handleNotes)
	router.POST("/notes/:noteid", handleNotesPost)
	router.GET("/systems/:sys", handleSystems)
	router.PUT("/vulnerability", handleVulnerabilityAdd)
	router.GET("/vulnerability", handleVulnerabilityPage)
	router.GET("/vulnerability/:vuln", handleVulnerabilities)
	router.GET("/vulnerability/:vuln/:field", handleVulnerabilityField)
	router.PUT("/vulnerability/:vuln/:field", handleVulnerabilityPut)
	router.POST("/vulnerability/:vuln/:field", handleVulnerabilityPost)
	router.DELETE("/vulnerability/:vuln/:field", handleVulnerabilityDelete)
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
		s := struct {
			Page string
			User interface{}
		}{"index", user}
		w.Header().Add("Content-Type", "text/html")
		err := templates.Lookup("index").Execute(w, s)
		if err != nil {
			fmt.Println(err)
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

// handleEmployeePage serves the employee page outline
func handleEmployeePage(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user.Authed {
		if user.Emp.Level == AdminUser {
			s := struct {
				Page string
				User interface{}
			}{"emp", user}
			w.Header().Add("Content-Type", "text/html")
			err := templates.Lookup("emps").Execute(w, s)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		} else {
			err := templates.Lookup("notauthorized-get").Execute(w, user)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// handleEmployees serves the employee objects
func handleEmployees(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	e := ps.ByName("emp")
	if user.Authed {
		if user.Emp.Level == AdminUser {
			switch e {
			case "all":
				emps, err := varsapi.GetEmployees()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				var data []interface{}
				for _, emp := range emps {
					s := struct {
						ID        int64
						FirstName string
						LastName  string
						Email     string
						UserName  string
						Level     int
					}{emp.ID, emp.FirstName, emp.LastName, emp.Email, emp.UserName, emp.Level}
					data = append(data, s)
				}
				err = json.NewEncoder(w).Encode(data)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			default:
				eid, err := strconv.Atoi(e)
				if err != nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				emp, err := varsapi.GetEmployeeByID(int64(eid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				err = json.NewEncoder(w).Encode(emp)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
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

// handleEmployeeAdd adds the new employee to VARS
func handleEmployeeAdd(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user.Authed {
		if user.Emp.Level == AdminUser {
			fname := r.FormValue("firstname")
			lname := r.FormValue("lastname")
			email := r.FormValue("email")
			uname := r.FormValue("username")
			l := r.FormValue("level")
			level, err := strconv.Atoi(l)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
			emp := varsapi.CreateEmployee(fname, lname, email, uname, level)
			err = varsapi.AddEmployee(db, emp)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			ist := struct {
				ID int64
			}{emp.ID}
			err = json.NewEncoder(w).Encode(ist)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else {
			err := templates.Lookup("notauthorized-get").Execute(w, user)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleEmployeePost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	e := ps.ByName("emp")
	eid, err := strconv.Atoi(e)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	field := ps.ByName("field")
	if user.Authed {
		switch field {
		case "name":
			if user.Emp.Level == AdminUser {
				fname := r.FormValue("firstname")
				lname := r.FormValue("lastname")
				err := varsapi.UpdateEmployeeName(db, int64(eid), fname, lname)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "email":
			if user.Emp.Level == AdminUser {
				email := r.FormValue("email")
				err := varsapi.UpdateEmployeeEmail(db, int64(eid), email)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "username":
			if user.Emp.Level == AdminUser {
				username := r.FormValue("username")
				err := varsapi.UpdateEmployeeUsername(db, int64(eid), username)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "level":
			if user.Emp.Level == AdminUser {
				l := r.FormValue("level")
				level, err := strconv.Atoi(l)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = varsapi.UpdateEmployeeLevel(db, int64(eid), level)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusTeapot)
			return
		}
	}
}

func handleNotes(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if user.Authed {
		if user.Emp.Level <= StandardUser {
			v := ps.ByName("vuln")
			vid, err := strconv.Atoi(v)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			ns, err := varsapi.GetNotes(int64(vid))
			if err != nil {
				if varsapi.IsNoRowsError(err) {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			var notes []interface{}
			for _, n := range ns {
				canEdit := user.Emp.ID == n.EmpID
				employee, err := varsapi.GetEmployeeByID(n.EmpID)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				note := struct {
					Nid      int64
					Emp      string
					Added    string
					Note     string
					Editable bool
				}{n.ID, fmt.Sprintf("%v %v", employee.FirstName, employee.LastName), n.Added.Format("Mon, 02 Jan 2006 15:04:05"), n.Note, canEdit}
				notes = append(notes, note)
			}
			err = json.NewEncoder(w).Encode(notes)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
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

func handleNotesPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if user.Authed {
		n := ps.ByName("noteid")
		nid, err := strconv.Atoi(n)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		author, err := varsapi.GetNoteAuthor(int64(nid))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if user.Emp.Level <= StandardUser && user.Emp.ID == author {
			note := r.FormValue("note")
			err = varsapi.UpdateNote(db, int64(nid), note)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
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

func handleSystems(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	s := ps.ByName("sys")
	if user.Authed {
		if user.Emp.Level <= StandardUser {
			switch s {
			case "all":
				syss, err := varsapi.GetSystems()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = json.NewEncoder(w).Encode(syss)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			case "active":
				syss, err := varsapi.GetActiveSystems()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = json.NewEncoder(w).Encode(syss)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			default:
				w.WriteHeader(http.StatusNotFound)
				return
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

// handleVulnerabilityAdd adds the new vuln to VARS
func handleVulnerabilityAdd(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user.Authed {
		if user.Emp.Level <= PrivilegedUser {
			name := r.FormValue("name")
			summ := r.FormValue("summary")
			cvss := r.FormValue("cvssScore")
			cvsl := r.FormValue("cvssLink")
			corp := r.FormValue("corpscore")
			test := r.FormValue("test")
			miti := r.FormValue("mitigation")
			expb := r.FormValue("exploitable")
			expl := r.FormValue("exploit")
			exploitable, err := strconv.ParseBool(expb)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			cScore, err := strconv.ParseFloat(cvss, 32)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			corpscore, err := strconv.ParseFloat(corp, 32)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			vuln := varsapi.CreateVulnerability(name, summ, cvsl, test, miti, expl, exploitable, float32(cScore), float32(corpscore))
			vuln.Finder = user.Emp.ID
			vuln.Initiator = user.Emp.ID
			err = varsapi.AddVulnerability(db, vuln)
			if err != nil {
				if varsapi.IsNameNotAvailableError(err) {
					w.WriteHeader(http.StatusNotAcceptable)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			ist := struct {
				ID int64
			}{vuln.ID}
			err = json.NewEncoder(w).Encode(ist)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else {
			err := templates.Lookup("notauthorized-get").Execute(w, user)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleVulnerabilityField(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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
			cve := ""
			cves, err := varsapi.GetCves(int64(vid))
			if err != nil {
				if !varsapi.IsNoRowsError(err) {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			sort.Strings(*cves)
			cve = strings.Join(*cves, ", ")
			s := struct {
				CVE string
			}{cve}
			err = json.NewEncoder(w).Encode(s)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// handleVulnerabilityPage serves the vulnerability page outline
func handleVulnerabilityPage(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user.Authed {
		if user.Emp.Level <= StandardUser {
			s := struct {
				Page string
				User interface{}
			}{"vuln", user}
			w.Header().Add("Content-Type", "text/html")
			err := templates.Lookup("vulns").Execute(w, s)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		} else {
			err := templates.Lookup("notauthorized-get").Execute(w, user)
			if err != nil {
				http.Error(w, "Error with templating", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// handleVulnerabilities serves the vulnerability objects
func handleVulnerabilities(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	v := ps.ByName("vuln")
	if user.Authed {
		if user.Emp.Level <= StandardUser {
			switch v {
			case "all":
				vulns, err := varsapi.GetVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				var data []interface{}
				for _, v := range vulns {
					cve := ""
					cves, err := varsapi.GetCves(v.ID)
					if err != nil {
						if !varsapi.IsNoRowsError(err) {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
					sort.Strings(*cves)
					cve = strings.Join(*cves, ", ")
					mit := ""
					if v.Dates.Mitigated.Valid {
						mit = v.Dates.Mitigated.Time.Format("Mon, 02 Jan 2006 15:04:05")
					}
					s := struct {
						ID        int64
						Name      string
						Summary   string
						Cvss      float32
						CorpScore float32
						Cve       string
						Initiated string
						Mitigated string
					}{v.ID, v.Name, v.Summary, v.Cvss, v.CorpScore, cve, v.Dates.Initiated.Format("Mon, 02 Jan 2006 15:04:05"), mit}
					data = append(data, s)
				}
				err = json.NewEncoder(w).Encode(data)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			case "open":
				vulns, err := varsapi.GetOpenVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				var data []interface{}
				for _, v := range vulns {
					cve := ""
					cves, err := varsapi.GetCves(v.ID)
					if err != nil {
						if !varsapi.IsNoRowsError(err) {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
					sort.Strings(*cves)
					cve = strings.Join(*cves, ", ")
					s := struct {
						ID        int64
						Name      string
						Summary   string
						Cvss      float32
						CorpScore float32
						Cve       string
						Initiated string
					}{v.ID, v.Name, v.Summary, v.Cvss, v.CorpScore, cve, v.Dates.Initiated.Format("Mon, 02 Jan 2006 15:04:05")}
					data = append(data, s)
				}
				err = json.NewEncoder(w).Encode(data)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			case "closed":
				vulns, err := varsapi.GetClosedVulnerabilities()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				var data []interface{}
				for _, v := range vulns {
					cve := ""
					cves, err := varsapi.GetCves(v.ID)
					if err != nil {
						if !varsapi.IsNoRowsError(err) {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
					sort.Strings(*cves)
					cve = strings.Join(*cves, ", ")
					var mit string
					if v.Dates.Mitigated.Valid {
						mit = v.Dates.Mitigated.Time.Format("Mon, 02 Jan 2006 15:04:05")
					} else {
						mit = ""
					}
					s := struct {
						ID        int64
						Name      string
						Summary   string
						Cvss      float32
						CorpScore float32
						Cve       string
						Initiated string
						Mitigated string
					}{v.ID, v.Name, v.Summary, v.Cvss, v.CorpScore, cve, v.Dates.Initiated.Format("Mon, 02 Jan 2006 15:04:05"), mit}
					data = append(data, s)
				}
				err = json.NewEncoder(w).Encode(data)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			default:
				vid, err := strconv.Atoi(v)
				if err != nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				vuln, err := varsapi.GetVulnerability(int64(vid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				err = json.NewEncoder(w).Encode(vuln)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
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
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "ticket":
			if user.Emp.Level <= StandardUser {
				ticket := r.FormValue("ticket")
				err := varsapi.AddTicket(db, int64(vid), ticket)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "ref":
			if user.Emp.Level <= StandardUser {
				ref := r.FormValue("ref")
				err := varsapi.AddRef(db, int64(vid), ref)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "affected":
			if user.Emp.Level <= StandardUser {
				sys := r.FormValue("system")
				sid, err := strconv.Atoi(sys)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				err = varsapi.AddAffected(db, int64(vid), int64(sid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "note":
			if user.Emp.Level <= StandardUser {
				note := r.FormValue("note")
				err := varsapi.AddNote(db, int64(vid), user.Emp.ID, note)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusTeapot)
			return
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
		case "ref":
			if user.Emp.Level <= StandardUser {
				b, err := ioutil.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				ref := string(b)
				err = varsapi.DeleteRef(db, int64(vid), ref)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "affected":
			if user.Emp.Level <= StandardUser {
				sys := ps.ByName("item")
				sid, err := strconv.Atoi(sys)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				err = varsapi.DeleteAffected(db, int64(vid), int64(sid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "note":
			n := ps.ByName("item")
			nid, err := strconv.Atoi(n)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			author, err := varsapi.GetNoteAuthor(int64(nid))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if user.Emp.Level <= StandardUser && user.Emp.ID == author {
				err = varsapi.DeleteNote(db, int64(nid))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusTeapot)
			return
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
		case "name":
			if user.Emp.Level <= PrivilegedUser {
				name := r.FormValue("name")
				err := varsapi.UpdateVulnerabilityName(db, int64(vid), name)
				if err != nil {
					if varsapi.IsNameNotAvailableError(err) {
						w.WriteHeader(http.StatusNotAcceptable)
						return
					}
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
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
		case "ref":
			if user.Emp.Level <= StandardUser {
				oldRef := r.FormValue("oldr")
				newRef := r.FormValue("newr")
				err := varsapi.UpdateReference(db, int64(vid), oldRef, newRef)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "exploitable":
			if user.Emp.Level <= StandardUser {
				exploitable := r.FormValue("exploitable")
				b, err := strconv.ParseBool(exploitable)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = varsapi.UpdateExploitable(db, int64(vid), b)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "exploit":
			if user.Emp.Level <= StandardUser {
				exploit := r.FormValue("exploit")
				err = varsapi.UpdateExploit(db, int64(vid), exploit)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "affected":
			if user.Emp.Level <= StandardUser {
				sys := ps.ByName("item")
				sid, err := strconv.Atoi(sys)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				patched := r.FormValue("patched")
				b, err := strconv.ParseBool(patched)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				err = varsapi.UpdateAffected(db, int64(vid), int64(sid), b)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusTeapot)
			return
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
