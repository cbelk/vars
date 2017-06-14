package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
)

func main() {
	// Read in the configuration
	err := vars.ReadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}

	// Start the database connection
	db, err := vars.ConnectDB(&vars.Conf)
	if err != nil {
		log.Fatal(err)
	}
	defer vars.CloseDB(db)
}

func handleRequest() {
	http.HandleFunc("/vuln/", serveVuln)

	err := http.ListenAndServe(":1843", nil)
	if err != nil {
		log.Fatal("Varsweb: ", err)
	}
}

func serveVuln(w http.ResponseWriter, r http.Request) {
	id := r.URL.Path[len("/vuln/"):]
	switch m := r.Method; m {
	case "GET":
		// Get vuln {id}
		b, err := varsapi.GetVulnerability(id)
		if err != nil {
			log.Printf("varsweb: serveVuln: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Add("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		// Update vuln {id}
		r.ParseForm()

	case "DELETE":
		// Delete vuln {id}
	default:
		// Not a valid endpoint
		w.WriteHeader(http.StatusBadRequest)
	}
}
