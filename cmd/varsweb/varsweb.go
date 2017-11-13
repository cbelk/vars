package main

import (
	"database/sql"
	//	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
)

var db *sql.DB

func main() {
	// Read in the configuration
	config := os.Getenv("VARS_CONFIG")
	if config == "" {
		log.Fatal("VarsWeb: VARS_CONFIG not set.")
	}
	err := vars.ReadConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Start the database connection
	db, err = vars.ConnectDB(&vars.Conf)
	if err != nil {
		log.Fatal(err)
	}
	defer vars.CloseDB(db)

	// Start handling request
	handleRequest()
}

func handleRequest() {
	http.HandleFunc("/vuln/", serveVuln)

	err := http.ListenAndServe(":1843", nil)
	if err != nil {
		log.Fatal("Varsweb: ", err)
	}
}

func serveVuln(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/vuln/"):]
	switch m := r.Method; m {
	case "GET":
		// Get vuln {id}
		b, err := varsapi.GetVulnerability(id)
		if err != nil {
			log.Printf("varsweb: serveVuln: GET: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			break
		}
		w.Header().Add("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		// Create vuln {id}
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("varsweb: serveVuln: PUT: ReadAll: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			break
		}
		err = varsapi.AddVulnerability(db, data)
		if err != nil {
			log.Printf("varsweb: serveVuln: PUT: AddVulnerability: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			break
		}
		w.WriteHeader(http.StatusOK)
	case "POST":
		// Update vuln {id}
	case "DELETE":
		// Delete vuln {id}
	default:
		// Not a valid endpoint
		w.WriteHeader(http.StatusBadRequest)
	}
}
