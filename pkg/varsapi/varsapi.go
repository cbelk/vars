package varsapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"strconv"

	"github.com/cbelk/vars"
)

// AddSystem adds a new system to the database.
func AddSystem(db *sql.DB, data []byte) error {
	//Start transaction and set rollback function
	log.Print("AddSystem: Starting transaction")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	// Get System object
	log.Print("AddSystem: Making sys from json")
	sys, err := makeSysFromJson(data)
	if err != nil {
		return err
	}

	// Add system
	log.Print("AddSystem: Adding sys")
	err = vars.InsertSystem(tx, sys)
	if ve, ok := err.(vars.Err); ok {
		if !vars.IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
		}
	} else if e, ok := err.(error); ok {
		return e
	}

	// Commit the transaction
	log.Print("AddSystem: Committing transaction")
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// DecommissionSystem sets the state of the given system to decommissioned.
func DecommissionSystem(db *sql.DB, data []byte) error {
	//Start transaction and set rollback function
	log.Print("DecommissionSystem: Starting transaction")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	// Get System object
	log.Print("DecommissionSystem: Making sys from json")
	sys, err := makeSysFromJson(data)
	if err != nil {
		return err
	}

	// Decommission system
	log.Print("DecommissionSystem: Decommissioning sys")
	err = vars.DecommissionSystem(tx, sys.Name)
	if ve, ok := err.(vars.Err); ok {
		if !vars.IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
		}
	} else if e, ok := err.(error); ok {
		return e
	}

	// Commit the transaction
	log.Print("DecommissionSystem: Committing transaction")
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

func AddVulnerability(db *sql.DB, data []byte) error {
	//Start transaction and set rollback function
	log.Print("AddVulnerability: Starting transaction")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	// Get Vulnerability object
	log.Print("AddVulnerability: Making vuln from json")
	vuln, err := makeVulnFromJson(data)
	if err != nil {
		return err
	}

	// Add vulnerability
	log.Print("AddVulnerability: Adding vuln")
	err = vars.AddVulnerability(tx, vuln)
	if err != nil {
		return err
	}

	// Commit the transaction
	log.Print("AddVulnerability: Committing transaction")
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// GetVulnerability retrieves/returns the vulnerability with the given id.
func GetVulnerability(id string) ([]byte, error) {
	vid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}
	vuln, err := vars.GetVulnerability(vid)
	if err != nil {
		return nil, err
	}
	return json.Marshal(vuln)
}

func UpdateVulnerability(db *sql.DB, v url.Values) error {
	// Get the vulnid
	id := v.Get("vulnid")
	if id == "" {
		return errors.New("UpdateVulnerability: Error: No vulnid in request")
	}
	vid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	//Start transaction and set rollback function
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	// Update vulnname
	if vname := v.Get("vulnname"); vname != "" {
		err = vars.UpdateVulnName(tx, vid, vname)
		if err != nil {
			return err
		}
	}

	// Update CVE

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

func makeSysFromJson(data []byte) (*vars.System, error) {
	var sys vars.System
	err := json.Unmarshal(data, &sys)
	return &sys, err
}

func makeVulnFromJson(data []byte) (*vars.Vulnerability, error) {
	var vuln vars.Vulnerability
	err := json.Unmarshal(data, &vuln)
	return &vuln, err
}
