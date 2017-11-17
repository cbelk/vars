package varsapi

import (
	"database/sql"
	"fmt"
	//	"encoding/json"
	//	"errors"
	//	"net/url"
	//	"strconv"

	"github.com/cbelk/vars"
)

// AddAffected adds a new vulnerability/system pair to the affected table
func AddAffected(db *sql.DB, vuln *vars.Vulnerability, sys *vars.System) error {
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

	// Add affected
	err = vars.InsertAffected(tx, vuln.ID, sys.ID)
	if !vars.IsNilErr(err) {
		return err
	}

	// Commit the transaction
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// AddSystem adds a new system to the database.
func AddSystem(db *sql.DB, sys *vars.System) error {
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

	// Check if system name is available
	a, err := vars.NameIsAvailable(*sys)
	if !vars.IsNilErr(err) {
		return err
	}
	if !a {
		return vars.ErrNameNotAvailable
	}

	// Add system
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
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// AddVulnerability starts a new VA
func AddVulnerability(db *sql.DB, vuln *vars.Vulnerability) error {
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

	// Check if vulnerability name is available
	a, err := vars.NameIsAvailable(*vuln)
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
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// DecommissionSystem sets the state of the given system to decommissioned.
func DecommissionSystem(db *sql.DB, sys *vars.System) error {
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

	// Decommission system
	err = vars.UpdateSysState(tx, sys.ID, "decommissioned")
	if !vars.IsNilErr(err) {
		return err
	}

	// Commit the transaction
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// GetSystem retieves/returns the system with the given id.
func GetSystem(sid int64) (*vars.System, error) {
	return vars.GetSystem(sid)
}

// GetSystemByName retieves/returns the system with the given name.
func GetSystemByName(name string) (*vars.System, error) {
	id, err := vars.GetSystemID(name)
	if !vars.IsNilErr(err) {
		var s vars.System
		return &s, err
	}
	return vars.GetSystem(id)
}

// GetVulnerability retrieves/returns the vulnerability with the given id.
func GetVulnerability(vid int64) (*vars.Vulnerability, error) {
	var v vars.Vulnerability

	// Get vulnerability fields
	vuln, err := vars.GetVulnerability(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}

	// Get dates
	vd, err := vars.GetVulnDates(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Dates = *vd

	// Get tickets
	ticks, err := vars.GetTickets(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Tickets = *ticks

	// Get references
	refs, err := vars.GetReferences(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.References = *refs

	// Get exploit
	exploit, exploitable, err := vars.GetExploit(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Exploit = exploit
	vuln.Exploitable = exploitable

	return vuln, nil
}

// GetVulnerabilityByName retrieves/returns the vulnerability with the given name.
func GetVulnerabilityByName(name string) (*vars.Vulnerability, error) {
	id, err := vars.GetVulnID(name)
	if !vars.IsNilErr(err) {
		var v vars.Vulnerability
		return &v, err
	}
	return GetVulnerability(id)
}

// UpdateSystem updates the edited parts of the system
func UpdateSystem(db *sql.DB, sys *vars.System) error {
	// Get the old system
	old, err := vars.GetSystem(sys.ID)
	if !vars.IsNilErr(err) {
		return err
	}

	// Start transaction and set rollback function
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

	// Compare old system object to new system object and update appropriate parts
	if old.Name != sys.Name {
		// Check new name
		a, err := vars.NameIsAvailable(*sys)
		if !vars.IsNilErr(err) {
			return err
		}
		if !a {
			return vars.ErrNameNotAvailable
		}

		// Update name
		err = vars.UpdateSysName(tx, sys.ID, sys.Name)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Type != sys.Type {
		err = vars.UpdateSysType(tx, sys.ID, sys.Type)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.OpSys != sys.OpSys {
		err = vars.UpdateSysOS(tx, sys.ID, sys.OpSys)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Location != sys.Location {
		err = vars.UpdateSysLoc(tx, sys.ID, sys.Location)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Description != sys.Description {
		err = vars.UpdateSysDesc(tx, sys.ID, sys.Description)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.State != sys.State {
		err = vars.UpdateSysState(tx, sys.ID, sys.State)
		if !vars.IsNilErr(err) {
			return err
		}
	}

	// Commit the transaction
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateVulnerability updates the edited parts of the vulnerability
func UpdateVulnerability(db *sql.DB, vuln *vars.Vulnerability) error {
	// Get the old vulnerability
	old, err := vars.GetVulnerability(vuln.ID)
	if !vars.IsNilErr(err) {
		return err
	}
	tickets, err := vars.GetTickets(vuln.ID)
	if !vars.IsNilErr(err) {
		return err
	}
	old.Tickets = *tickets
	refs, err := vars.GetReferences(vuln.ID)
	if !vars.IsNilErr(err) {
		return err
	}
	old.References = *refs

	// Start transaction and set rollback function
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

	// Compare old vulnerability object to new vulnerability object and update appropriate parts
	if old.Name != vuln.Name {
		// Check new name
		a, err := vars.NameIsAvailable(*vuln)
		if !vars.IsNilErr(err) {
			return err
		}
		if !a {
			return vars.ErrNameNotAvailable
		}

		// Update name
		err = vars.UpdateVulnName(tx, vuln.ID, vuln.Name)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Cve != vuln.Cve {
		err = vars.UpdateCve(tx, vuln.ID, vuln.Cve)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Cvss != vuln.Cvss {
		err = vars.UpdateCvss(tx, vuln.ID, vuln.Cvss)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.CorpScore != vuln.CorpScore {
		err = vars.UpdateCorpScore(tx, vuln.ID, vuln.CorpScore)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.CvssLink != vuln.CvssLink {
		err = vars.UpdateCvssLink(tx, vuln.ID, vuln.CvssLink)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Finder != vuln.Finder {
		err = vars.UpdateFinder(tx, vuln.ID, vuln.Finder)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Initiator != vuln.Initiator {
		err = vars.UpdateInitiator(tx, vuln.ID, vuln.Initiator)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Summary != vuln.Summary {
		err = vars.UpdateSummary(tx, vuln.ID, vuln.Summary)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Test != vuln.Test {
		err = vars.UpdateTest(tx, vuln.ID, vuln.Test)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Mitigation != vuln.Mitigation {
		err = vars.UpdateMitigation(tx, vuln.ID, vuln.Mitigation)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Dates.Published != vuln.Dates.Published {
		err = vars.UpdatePubDate(tx, vuln.ID, vuln.Dates.Published)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Dates.Initiated != vuln.Dates.Initiated {
		err = vars.UpdateInitDate(tx, vuln.ID, vuln.Dates.Initiated)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Dates.Mitigated != vuln.Dates.Mitigated {
		err = vars.UpdateMitDate(tx, vuln.ID, vuln.Dates.Mitigated)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if vuln.Exploit.Valid {
		if old.Exploit.Valid {
			if old.Exploit.String != vuln.Exploit.String {
				err = vars.UpdateExploit(tx, vuln.ID, vuln.Exploit.String)
				if !vars.IsNilErr(err) {
					return err
				}
			}
		}
		err = vars.UpdateExploit(tx, vuln.ID, vuln.Exploit.String)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	err = UpdateTickets(tx, old, vuln)
	if !vars.IsNilErr(err) {
		return err
	}
	err = UpdateReferences(tx, old, vuln)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateReferences determines the rows that need to be deleted/added and calls the appropriate VARS function.
func UpdateReferences(tx *sql.Tx, old, vuln *vars.Vulnerability) error {
	del := toBeDeleted(&old.References, &vuln.References)
	for _, ref := range *del {
		err := vars.DeleteRef(tx, vuln.ID, ref)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	add := toBeAdded(&old.References, &vuln.References)
	for _, ref := range *add {
		err := vars.InsertRef(tx, vuln.ID, ref)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	return nil
}

// UpdateTickets determines the rows that need to be deleted/added and calls the appropriate VARS function.
func UpdateTickets(tx *sql.Tx, old, vuln *vars.Vulnerability) error {
	del := toBeDeleted(&old.Tickets, &vuln.Tickets)
	for _, tick := range *del {
		err := vars.DeleteTicket(tx, vuln.ID, tick)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	add := toBeAdded(&old.Tickets, &vuln.Tickets)
	for _, tick := range *add {
		err := vars.InsertTicket(tx, vuln.ID, tick)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	return nil
}

// stringInSlice searches for the given string in the given slice and returns a boolean value indicating whether
// the string is contained in the slice.
func stringInSlice(str string, slice *[]string) bool {
	for _, item := range *slice {
		if item == str {
			return true
		}
	}
	return false
}

// toBeAdded creates a slice of items that are in the new slice but not the old.
func toBeAdded(oldSlice, newSlice *[]string) *[]string {
	var add []string
	for _, item := range *newSlice {
		if !stringInSlice(item, oldSlice) {
			add = append(add, item)
		}
	}
	return &add
}

// toBeDeleted creates a slice of items that are in the old slice but not the new.
func toBeDeleted(oldSlice, newSlice *[]string) *[]string {
	var del []string
	for _, item := range *oldSlice {
		if !stringInSlice(item, newSlice) {
			del = append(del, item)
		}
	}
	return &del
}
