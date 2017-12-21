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

package varsapi

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cbelk/vars"
	"github.com/lib/pq"
)

// AddAffected adds a new vulnerability/system pair to the affected table
func AddAffected(db *sql.DB, vid, sid int64) error {
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
	err = vars.InsertAffected(tx, vid, sid, false)
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

// AddCve adds the given cve to the impact table for vulnid
func AddCve(db *sql.DB, vid int64, cve string) error {
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

	err = vars.InsertCve(tx, vid, cve)
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

// AddEmployee inserts a new employee into the database.
func AddEmployee(db *sql.DB, emp *vars.Employee) error {
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

	// Add employee
	err = vars.InsertEmployee(tx, emp.FirstName, emp.LastName, emp.Email, emp.UserName, emp.Level)
	if !vars.IsNilErr(err) {
		return err
	}

	// Update the employee ID
	id, err := vars.GetEmpIDtx(tx, emp.UserName)
	if !vars.IsNilErr(err) {
		return err
	}
	emp.ID = id

	// Commit the transaction
	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// AddNote inserts a new note into the database.
func AddNote(db *sql.DB, vid, eid int64, note string) error {
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

	// Add note
	err = vars.InsertNote(tx, vid, eid, note)
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

// AddRef adds the given reference to the ref table for vulnid.
func AddRef(db *sql.DB, vid int64, ref string) error {
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

	err = vars.InsertRef(tx, vid, ref)
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

// AddTicket adds the given ticket to the ticket table for vulnid
func AddTicket(db *sql.DB, vid int64, ticket string) error {
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

	err = vars.InsertTicket(tx, vid, ticket)
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
	a, err := vars.NameIsAvailable("sys", sys.Name)
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

// CreateEmployee creates an employee object with the given parameters.
func CreateEmployee(firstname, lastname, email, username string, level int) *vars.Employee {
	emp := vars.Employee{FirstName: firstname, LastName: lastname, Email: email, UserName: username, Level: level}
	return &emp
}

// CreateVulnerability creates a vulnerability object with the given parameters.
func CreateVulnerability(name, summary, cvssLink, test, mitigation, exploit string, exploitable bool, cvss, corpscore float32) *vars.Vulnerability {
	vuln := vars.Vulnerability{Name: name, Cvss: cvss, CorpScore: corpscore, CvssLink: GetVarsNullString(cvssLink), Summary: summary, Test: test, Mitigation: mitigation, Exploit: GetVarsNullString(exploit), Exploitable: GetVarsNullBool(exploitable)}
	return &vuln
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
	a, err := vars.NameIsAvailable("vuln", vuln.Name)
	if !vars.IsNilErr(err) {
		return err
	}
	if !a {
		return vars.NewErr(vars.NameNotAvailable, "VARS", "varsapi", "AddVulnerability")
	}

	// Insert the vulnerability into the database
	err = vars.InsertVulnerability(tx, vuln.Name, vuln.Finder, vuln.Initiator, vuln.Summary, vuln.Test, vuln.Mitigation)
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
	err = vars.InsertDates(tx, vuln.ID, time.Now(), vuln.Dates.Published, vuln.Dates.Mitigated)
	if !vars.IsNilErr(err) {
		return err
	}

	// Insert the values in the cves table
	err = vars.SetCves(tx, vuln)
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

// ReopenVulnerability sets the 'mitigated' date to a null date for the given vulnid.
func ReopenVulnerability(db *sql.DB, vid int64) error {
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

	date := vars.VarsNullTime{pq.NullTime{Time: time.Now(), Valid: false}}
	err = vars.UpdateMitDate(tx, vid, date)
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

// CloseVulnerability sets the 'mitigated' date equal to the date parameter for the given vulnid.
func CloseVulnerability(db *sql.DB, vid int64) error {
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

	date := GetVarsNullTime(time.Now())
	err = vars.UpdateMitDate(tx, vid, date)
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

// CloseDB is a way to close connections to the database safely
func CloseDB(db *sql.DB) {
	vars.CloseDB(db)
}

// ConnectDB gets the VARS config object and calls the VARS function to set up the database connection.
func ConnectDB() (*sql.DB, error) {
	conf := GetConfig()
	return vars.ConnectDB(&conf)
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

// DeleteAffected deletes the row (vid, sid) from affected.
func DeleteAffected(db *sql.DB, vid, sid int64) error {
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

	// Delete the row (vid, sid) from affected.
	err = vars.DeleteAffected(tx, vid, sid)
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

// DeleteCve will delete the row (vulnid, cve).
func DeleteCve(db *sql.DB, vid int64, cve string) error {
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

	err = vars.DeleteCve(tx, vid, cve)
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

// DeleteNote deletes the note with the given noteid.
func DeleteNote(db *sql.DB, nid int64) error {
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

	// Delete the note (nid)
	err = vars.DeleteNote(tx, nid)
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

// DeleteRef will delete the row in the ref table associated with (vid, ref).
func DeleteRef(db *sql.DB, vid int64, ref string) error {
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

	err = vars.DeleteRef(tx, vid, ref)
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

// DeleteTicket will delete the row (vulnid, ticket).
func DeleteTicket(db *sql.DB, vid int64, ticket string) error {
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

	err = vars.DeleteTicket(tx, vid, ticket)
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

// DeleteVulnerability will delete the vulnerability with the given vulnid from VARS.
func DeleteVulnerability(db *sql.DB, vid int64) error {
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

	// Delete from CVEs table
	cves, err := vars.GetCves(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	for _, cve := range *cves {
		err = vars.DeleteCve(tx, vid, cve)
		if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
			return err
		}
	}

	// Delete from Tickets table
	tickets, err := vars.GetTickets(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	for _, ticket := range *tickets {
		err = vars.DeleteTicket(tx, vid, ticket)
		if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
			return err
		}
	}

	// Delete from Affected table
	affected, err := vars.GetAffected(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	for _, aff := range affected {
		err = vars.DeleteAffected(tx, vid, aff.Sys.ID)
		if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
			return err
		}
	}

	// Delete from Notes table
	notes, err := vars.GetNotes(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	for _, note := range notes {
		err = vars.DeleteNote(tx, note.ID)
		if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
			return err
		}
	}

	// Delete from Ref table
	refs, err := vars.GetReferences(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	for _, ref := range *refs {
		err = vars.DeleteRef(tx, vid, ref)
		if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
			return err
		}
	}

	// Delete from Exploits table
	err = vars.DeleteExploit(tx, vid)
	if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
		return err
	}

	// Delete from Dates table
	err = vars.DeleteDates(tx, vid)
	if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
		return err
	}

	// Delete from Impact table
	err = vars.DeleteImpact(tx, vid)
	if !vars.IsNilErr(err) && !vars.IsNoRowsError(err) {
		return err
	}

	// Delete from vuln table
	err = vars.DeleteVulnerability(tx, vid)
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

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems() ([]*vars.System, error) {
	return vars.GetActiveSystems()
}

// GetEmployeeByID returns an Employee object with the given empid.
func GetEmployeeByID(eid int64) (*vars.Employee, error) {
	return vars.GetEmployee(eid)
}

// GetEmployeeByUsername returns an Employee object with the given username.
func GetEmployeeByUsername(username string) (*vars.Employee, error) {
	id, err := vars.GetEmpID(username)
	if !vars.IsNilErr(err) {
		var emp vars.Employee
		return &emp, err
	}
	return vars.GetEmployee(id)
}

// GetEmployees returns a slice of pointers to Employee objects.
func GetEmployees() ([]*vars.Employee, error) {
	return vars.GetEmployees()
}

// GetClosedVulnerabilities builds/returns a slice of pointers to Vulnerabilities that
// have a non-NULL 'mitigated' date.
func GetClosedVulnerabilities() ([]*vars.Vulnerability, error) {
	var vulns []*vars.Vulnerability

	// Get a slice of IDs associated with open vulnerabilities
	ids, err := vars.GetClosedVulnIDs()
	if !vars.IsNilErr(err) {
		return vulns, err
	}

	// For each ID get the associated vulnerability object
	for _, id := range *ids {
		vuln, err := GetVulnerability(id)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

// GetConfig retrieves/returns the Config object that was created in VARS.
func GetConfig() vars.Config {
	return vars.Conf
}

// GetCves returns a pointer to a slice of cves associated with the vulnid.
func GetCves(vid int64) (*[]string, error) {
	return vars.GetCves(vid)
}

// GetNoteAuthor returns the empid of the author of the note.
func GetNoteAuthor(noteid int64) (int64, error) {
	return vars.GetNoteAuthor(noteid)
}

// GetNotes retrieves/returns a slice of pointers to all note objects for the given vulnid.
func GetNotes(vid int64) ([]*vars.Note, error) {
	return vars.GetNotes(vid)
}

// GetOpenVulnerabilities builds/returns a slice of pointers to Vulnerabilities that
// have a NULL 'mitigated' date.
func GetOpenVulnerabilities() ([]*vars.Vulnerability, error) {
	var vulns []*vars.Vulnerability

	// Get a slice of IDs associated with open vulnerabilities
	ids, err := vars.GetOpenVulnIDs()
	if !vars.IsNilErr(err) {
		return vulns, err
	}

	// For each ID get the associated vulnerability object
	for _, id := range *ids {
		vuln, err := GetVulnerability(id)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

// GetSystem retrieves/returns the system with the given id.
func GetSystem(sid int64) (*vars.System, error) {
	return vars.GetSystem(sid)
}

// GetSystemByName retrieves/returns the system with the given name.
func GetSystemByName(name string) (*vars.System, error) {
	id, err := vars.GetSystemID(name)
	if !vars.IsNilErr(err) {
		var s vars.System
		return &s, err
	}
	return vars.GetSystem(id)
}

// GetSystems retrieves/returns a slice of pointers to all System objects.
func GetSystems() ([]*vars.System, error) {
	return vars.GetSystems()
}

// GetVarsNullBool creates/returns a VarsNullBool object using the given boolean paramter.
func GetVarsNullBool(b bool) vars.VarsNullBool {
	return vars.VarsNullBool{sql.NullBool{Bool: b, Valid: true}}
}

// GetVarsNullString creates/returns a VarsNullString object using the given string paramter.
func GetVarsNullString(str string) vars.VarsNullString {
	return vars.VarsNullString{sql.NullString{String: str, Valid: true}}
}

// GetVarsNullTime creates/returns a VarsNullTime object using the given time paramter.
func GetVarsNullTime(t time.Time) vars.VarsNullTime {
	return vars.VarsNullTime{pq.NullTime{Time: t, Valid: true}}
}

// GetVulnID returns the vulnid associated with the vname.
func GetVulnID(vname string) (int64, error) {
	return vars.GetVulnID(vname)
}

// GetVulnerabilities retrieves/returns all vulnerabilities.
func GetVulnerabilities() ([]*vars.Vulnerability, error) {
	// Get vulnerabilities (vuln fields)
	vulns, err := vars.GetVulnerabilities()
	if !vars.IsNilErr(err) {
		return vulns, err
	}

	for _, vuln := range vulns {
		//Get impact
		cvss, cvssLink, cscore, err := vars.GetImpact(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.Cvss = cvss
		vuln.CvssLink = cvssLink
		vuln.CorpScore = cscore

		// Get dates
		vd, err := vars.GetVulnDates(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.Dates = *vd

		// Get cves
		cves, err := vars.GetCves(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.Cves = *cves

		// Get tickets
		ticks, err := vars.GetTickets(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.Tickets = *ticks

		// Get references
		refs, err := vars.GetReferences(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.References = *refs

		// Get exploit
		exploit, exploitable, err := vars.GetExploit(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.Exploit = exploit
		vuln.Exploitable = exploitable

		// Get affected
		affs, err := vars.GetAffected(vuln.ID)
		if !vars.IsNilErr(err) {
			return vulns, err
		}
		vuln.AffSystems = affs
	}
	return vulns, nil
}

// GetVulnerability retrieves/returns the vulnerability with the given id.
func GetVulnerability(vid int64) (*vars.Vulnerability, error) {
	var v vars.Vulnerability

	// Get vulnerability fields
	vuln, err := vars.GetVulnerability(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}

	//Get impact
	cvss, cvssLink, cscore, err := vars.GetImpact(vuln.ID)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Cvss = cvss
	vuln.CvssLink = cvssLink
	vuln.CorpScore = cscore

	// Get dates
	vd, err := vars.GetVulnDates(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Dates = *vd

	// Get Cves
	cves, err := vars.GetCves(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.Cves = *cves

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

	// Get affected
	affs, err := vars.GetAffected(vuln.ID)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	vuln.AffSystems = affs

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

// IsNameNotAvailableError returns true if the error is caused by name not being available
func IsNameNotAvailableError(err error) bool {
	return vars.IsNameNotAvailableError(err)
}

// IsNoRowsError returns true if the error is caused by no rows being effected
func IsNoRowsError(err error) bool {
	return vars.IsNoRowsError(err)
}

// ReadConfig passes the config string to vars.ReadConfig to create the Config object.
func ReadConfig(config string) error {
	return vars.ReadConfig(config)
}

// UpdateAffected will update the mitigated status of the row (vid, sid).
func UpdateAffected(db *sql.DB, vid, sid int64, mit bool) error {
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

	err = vars.UpdateAffected(tx, vid, sid, mit)
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

// UpdateCvss will update the cvss score and link if they have been changed.
func UpdateCvss(db *sql.DB, vid int64, cvss float32, link string) error {
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

	c, cl, _, err := vars.GetImpact(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	if cvss != c {
		err = vars.UpdateCvss(tx, vid, cvss)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if (cl.Valid && link != cl.String) || !cl.Valid {
		vnl := GetVarsNullString(link)
		err = vars.UpdateCvssLink(tx, vid, vnl)
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

// UpdateEmployee will update the row in the emp table with the new employee information.
func UpdateEmployee(db *sql.DB, emp *vars.Employee) error {
	// Get the old employee
	old, err := GetEmployeeByID(emp.ID)
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

	// Compare old employee object to new employee object and update appropriate parts
	if old.FirstName != emp.FirstName {
		err = vars.UpdateEmpFname(tx, emp.ID, emp.FirstName)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.LastName != emp.LastName {
		err = vars.UpdateEmpLname(tx, emp.ID, emp.LastName)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Email != emp.Email {
		err = vars.UpdateEmpEmail(tx, emp.ID, emp.Email)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.UserName != emp.UserName {
		err = vars.UpdateEmpUname(tx, emp.ID, emp.UserName)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	if old.Level != emp.Level {
		err = vars.UpdateEmpLevel(tx, emp.ID, emp.Level)
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

// UpdateEmployeeEmail will update the email associated with the given empid.
func UpdateEmployeeEmail(db *sql.DB, eid int64, email string) error {
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

	err = vars.UpdateEmpEmail(tx, eid, email)
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

// UpdateEmployeeLevel will update the level associated with the given empid.
func UpdateEmployeeLevel(db *sql.DB, eid int64, level int) error {
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

	err = vars.UpdateEmpLevel(tx, eid, level)
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

// UpdateEmployeeName will update the first/last name associated with the given empid.
func UpdateEmployeeName(db *sql.DB, eid int64, fname, lname string) error {
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

	err = vars.UpdateEmpFname(tx, eid, fname)
	if !vars.IsNilErr(err) {
		return err
	}
	err = vars.UpdateEmpLname(tx, eid, lname)
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

// UpdateEmployeeUsername will update the username associated with the given empid.
func UpdateEmployeeUsername(db *sql.DB, eid int64, username string) error {
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

	err = vars.UpdateEmpUname(tx, eid, username)
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

// UpdateExploit will update the exploit associated with vulnid.
func UpdateExploit(db *sql.DB, vid int64, exploit string) error {
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

	err = vars.UpdateExploit(tx, vid, exploit)
	if !vars.IsNilErr(err) {
		if vars.IsNoRowsError(err) {
			err = vars.InsertExploit(tx, vid, true, exploit)
			if !vars.IsNilErr(err) {
				return err
			}
		} else {
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

// UpdateExploitable will update the exploitable boolean associated with vulnid.
func UpdateExploitable(db *sql.DB, vid int64, exploitable bool) error {
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

	err = vars.UpdateExploitable(tx, vid, exploitable)
	if !vars.IsNilErr(err) {
		if vars.IsNoRowsError(err) {
			err = vars.InsertExploit(tx, vid, exploitable, "")
			if !vars.IsNilErr(err) {
				return err
			}
		} else {
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

// UpdateNote will update the note with the given noteid.
func UpdateNote(db *sql.DB, noteid int64, note string) error {
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

	err = vars.UpdateNote(tx, noteid, note)
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
		a, err := vars.NameIsAvailable("sys", sys.Name)
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

// UpdateVulnerabilityMitigation will update the mitigation associated with the given vulnid.
func UpdateVulnerabilityMitigation(db *sql.DB, vid int64, mitigation string) error {
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

	err = vars.UpdateMitigation(tx, vid, mitigation)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateVulnerabilityName updates the name associated with the given vulnid.
func UpdateVulnerabilityName(db *sql.DB, vid int64, name string) error {
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

	a, err := vars.NameIsAvailable("vuln", name)
	if !vars.IsNilErr(err) {
		return err
	}
	if !a {
		return vars.NewErr(vars.NameNotAvailable, "VARS", "varsapi", "UpdateVulnerabilityName")
	}
	err = vars.UpdateVulnName(tx, vid, name)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateVulnerabilitySummary updates the summary associated with the given vulnid.
func UpdateVulnerabilitySummary(db *sql.DB, vid int64, summary string) error {
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

	err = vars.UpdateSummary(tx, vid, summary)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateVulnerabilityTest will update the test associated with the given vulnid.
func UpdateVulnerabilityTest(db *sql.DB, vid int64, test string) error {
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

	err = vars.UpdateTest(tx, vid, test)
	if !vars.IsNilErr(err) {
		return err
	}

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
		a, err := vars.NameIsAvailable("vuln", vuln.Name)
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
	// Check (and update if needed) the published time
	opt, err := old.Dates.Published.Value()
	if err != nil {
		return err
	}
	npt, err := vuln.Dates.Published.Value()
	if err != nil {
		return err
	}
	if opt != nil && npt != nil {
		opd, ok := opt.(time.Time)
		if !ok {
			return errors.New("Varsapi: UpdateVulnerability: Failed to assert type for old published date.")
		}
		npd, ok := npt.(time.Time)
		if !ok {
			return errors.New("Varsapi: UpdateVulnerability: Failed to assert type for new published date")
		}
		if !opd.Equal(npd) {
			err = vars.UpdatePubDate(tx, vuln.ID, vuln.Dates.Published)
			if !vars.IsNilErr(err) {
				return err
			}
		}
	} else if opt == nil && npt != nil {
		err = vars.UpdatePubDate(tx, vuln.ID, vuln.Dates.Published)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	// Check (and update if needed) the initiated time
	if !old.Dates.Initiated.Equal(vuln.Dates.Initiated) {
		err = vars.UpdateInitDate(tx, vuln.ID, vuln.Dates.Initiated)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	// Check (and update if needed) the mitigated time
	omt, err := old.Dates.Mitigated.Value()
	if err != nil {
		return err
	}
	nmt, err := vuln.Dates.Mitigated.Value()
	if err != nil {
		return err
	}
	if omt != nil && nmt != nil {
		omd, ok := omt.(time.Time)
		if !ok {
			return errors.New("Varsapi: UpdateVulnerability: Failed to assert type for old mitigated date")
		}
		nmd, ok := nmt.(time.Time)
		if !ok {
			return errors.New("Varsapi: UpdateVulnerability: Failed to assert type for new mitigated date")
		}
		if !omd.Equal(nmd) {
			err = vars.UpdateMitDate(tx, vuln.ID, vuln.Dates.Mitigated)
			if !vars.IsNilErr(err) {
				return err
			}
		}
	} else if omt == nil && nmt != nil {
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
	err = UpdateCves(tx, old, vuln)
	if !vars.IsNilErr(err) {
		return err
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

// UpdateCorpscore will update the corpscore associated with the given vulnid.
func UpdateCorpScore(db *sql.DB, vid int64, corpscore float32) error {
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

	err = vars.UpdateCorpScore(tx, vid, corpscore)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateCve will update the CVE associated with the row (vid, cve).
func UpdateCve(db *sql.DB, vid int64, oldcve, newcve string) error {
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

	err = vars.UpdateCve(tx, vid, oldcve, newcve)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateCves determines the rows that need to be deleted/added and calls the appropriate VARS function.
func UpdateCves(tx *sql.Tx, old, vuln *vars.Vulnerability) error {
	del := toBeDeleted(&old.Cves, &vuln.Cves)
	for _, cve := range *del {
		err := vars.DeleteCve(tx, vuln.ID, cve)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	add := toBeAdded(&old.Cves, &vuln.Cves)
	for _, cve := range *add {
		err := vars.InsertCve(tx, vuln.ID, cve)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	return nil
}

// UpdateFinder will update the finder's empid associated with the vulnid
func UpdateFinder(db *sql.DB, vid, eid int64) error {
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

	err = vars.UpdateFinder(tx, vid, eid)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}

// UpdateReference will update the reference associated with row (vid, oldRef) to newRef.
func UpdateReference(db *sql.DB, vid int64, oldRef, newRef string) error {
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

	err = vars.UpdateRefers(tx, vid, oldRef, newRef)
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

// UpdateTicket will update the ticket associated with the row (vid, ticket).
func UpdateTicket(db *sql.DB, vid int64, oldticket, newticket string) error {
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

	err = vars.UpdateTicket(tx, vid, oldticket, newticket)
	if !vars.IsNilErr(err) {
		return err
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
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
