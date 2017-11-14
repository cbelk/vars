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

// AddAffected adds a new vulnerability/system pair to the affected table
func AddAffected(db *sql.DB, vuln *vars.Vulnerability, sys *vars.System) error {
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

	// Add affected
	log.Print("AddAffected: Adding affected system")
	err = vars.InsertAffected(tx, vuln.ID, sys.ID)
	if !vars.IsNilErr(err) {
		return err
	}

	// Commit the transaction
	log.Print("AddAffected: Committing transaction")
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// AddSystem adds a new system to the database.
func AddSystem(db *sql.DB, sys *vars.System) error {
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

	// Update the sysid
	id, err := vars.GetSystemIDtx(tx, sys.Name)
	if !vars.IsNilErr(err) {
		return err
	}
	sys.ID = id

	// Commit the transaction
	log.Print("AddSystem: Committing transaction")
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// AddVulnerability starts a new VA
func AddVulnerability(db *sql.DB, vuln *vars.Vulnerability) error {
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

	// Check if vulnerability name is available
	a, err := vars.NameIsAvailable(vuln.Name)
	if !vars.IsNilErr(err) {
		return err
	}
	if !a {
		return vars.ErrNameNotAvailable
	}

	// Insert the vulnerability into the database
	err = vars.InsertVulnerability(tx, vuln.Name, vuln.Cve, vuln.Finder, vuln.Initiator, vuln.Summary, vuln.Test, vuln.Mitigation)
	if !vars.IsNilErr(err) {
		return err
	}

	// Update the vulnid
	vid, err := vars.GetVulnIDtx(tx, vuln.Name)
	if !vars.IsNilErr(err) {
		return err
	}
	vuln.ID = vid

	// Insert the values in the impact table
	err = vars.InsertImpact(tx, vuln.ID, vuln.Cvss, vuln.CorpScore, vuln.CvssLink)
	if !vars.IsNilErr(err) {
		return err
	}

	// Insert the values in the dates table
	err = vars.InsertDates(tx, vuln.ID, vuln.Dates.Initiated, vuln.Dates.Published, vuln.Dates.Mitigated)
	if !vars.IsNilErr(err) {
		return err
	}

	// Insert the values in the ticket table
	err = vars.SetTickets(tx, vuln)
	if !vars.IsNilErr(err) {
		return err
	}

	// Insert the values in the reference table
	err = vars.SetReferences(tx, vuln)
	if !vars.IsNilErr(err) {
		return err
	}

	// Insert the values in the exploits table
	err = vars.SetExploit(tx, vuln)
	if !vars.IsNilErr(err) {
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

// DecommissionSystem sets the state of the given system to decommissioned.
func DecommissionSystem(db *sql.DB, sys *vars.System) error {
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

	// Decommission system
	log.Print("DecommissionSystem: Decommissioning ", sys)
	err = vars.UpdateSysState(tx, sys.ID, "decommissioned")
	if !vars.IsNilErr(err) {
		return err
	}

	// Commit the transaction
	log.Print("DecommissionSystem: Committing transaction")
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
