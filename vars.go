// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
	"database/sql"

	_ "github.com/lib/pq" // Postgresql driver
)

type sqlStatement int

const (
	ssActiveSystems sqlStatement = iota
	ssCheckVulnName
	ssCheckSysName
	ssGetExploit
	ssGetReferences
	ssGetSystem
	ssGetSystems
	ssGetSystemID
	ssGetTickets
	ssGetVuln
	ssGetVulns
	ssGetVulnDates
	ssGetVulnID
	ssInsertAffected
	ssInsertDates
	ssInsertEmployee
	ssInsertExploit
	ssInsertImpact
	ssInsertRefers
	ssInsertSystem
	ssInsertTicket
	ssInsertVuln
	ssUpdateAffected
	ssUpdateCve
	ssUpdateCvss
	ssUpdateCvssLink
	ssUpdateCorpScore
	ssUpdateExploit
	ssUpdateFinder
	ssUpdateInitiator
	ssUpdateInitDate
	ssUpdateMitDate
	ssUpdateMitigation
	ssUpdatePubDate
	ssUpdateRefers
	ssUpdateSummary
	ssUpdateSysName
	ssUpdateSysType
	ssUpdateSysOS
	ssUpdateSysLoc
	ssUpdateSysDesc
	ssUpdateSysState
	ssUpdateTest
	ssUpdateTicket
	ssUpdateVulnName
)

// SQL queries to be used in program execution.
var (
	queries      map[sqlStatement]*sql.Stmt
	queryStrings = map[sqlStatement]string{
		ssActiveSystems:    "SELECT sysid, sysname, systype, opsys, location, description FROM systems WHERE state='active';",
		ssCheckVulnName:    "SELECT vulnid FROM vuln WHERE vulnname=$1;",
		ssCheckSysName:     "SELECT sysid FROM systems WHERE sysname=$1;",
		ssGetExploit:       "SELECT exploitable, exploit FROM exploits WHERE vulnid=$1;",
		ssGetReferences:    "SELECT url FROM ref WHERE vulnid=$1;",
		ssGetSystem:        "SELECT sysname, systype, opsys, location, description, state FROM systems WHERE sysid=$1;",
		ssGetSystems:       "SELECT sysid, sysname, systype, opsys, location, description, state FROM systems;",
		ssGetSystemID:      "SELECT sysid FROM systems WHERE sysname=$1;",
		ssGetTickets:       "SELECT ticket FROM tickets WHERE vulnid=$1;",
		ssGetVuln:          "SELECT vulnname, cve, finder, initiator, summary, test, mitigation FROM vuln WHERE vulnid=$1;",
		ssGetVulns:         "SELECT vulnid, vulnname, cve, finder, initiator, summary, test, mitigation FROM vuln;",
		ssGetVulnDates:     "SELECT published, initiated, mitigated FROM dates WHERE vulnid=$1;",
		ssGetVulnID:        "SELECT vulnid FROM vuln WHERE vulnname=$1;",
		ssInsertAffected:   "INSERT INTO affected (vulnid, sysid) VALUES ($1, $2);",
		ssInsertDates:      "INSERT INTO dates (vulnid, published, initiated, mitigated) VALUES ($1, $2, $3, $4);",
		ssInsertEmployee:   "INSERT INTO emp (firstname, lastname, email) VALUES ($1, $2, $3);",
		ssInsertExploit:    "INSERT INTO exploits (vulnid, exploitable, exploit) VALUES ($1, $2, $3);",
		ssInsertImpact:     "INSERT INTO impact (vulnid, cvss, cvsslink, corpscore) VALUES ($1, $2, $3, $4);",
		ssInsertRefers:     "INSERT INTO ref (vulnid, url) VALUES ($1, $2);",
		ssInsertSystem:     "INSERT INTO systems (sysname, systype, opsys, location, description, state) VALUES ($1, $2, $3, $4, $5, $6);",
		ssInsertTicket:     "INSERT INTO tickets (vulnid, ticket) VALUES ($1, $2);",
		ssInsertVuln:       "INSERT INTO vuln (vulnname, cve, finder, initiator, summary, test, mitigation) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING vulnid;",
		ssUpdateAffected:   "UPDATE affected SET sysid=$1 WHERE vulnid=$2 AND sysid=$3;",
		ssUpdateCve:        "UPDATE vuln SET cve=$1 WHERE vulnid=$2;",
		ssUpdateCvss:       "UPDATE impact SET cvss=$1 WHERE vulnid=$2;",
		ssUpdateCvssLink:   "UPDATE impact SET cvsslink=$1 WHERE vulnid=$2;",
		ssUpdateCorpScore:  "UPDATE impact SET corpscore=$1 WHERE vulnid=$2;",
		ssUpdateExploit:    "UPDATE exploits SET exploitable=$1, exploit=$2 WHERE vulnid=$3;",
		ssUpdateFinder:     "UPDATE vuln SET finder=$1 WHERE vulnid=$2;",
		ssUpdateInitiator:  "UPDATE vuln SET initiator=$1 WHERE vulnid=$2;",
		ssUpdateInitDate:   "UPDATE dates SET initiated=$1 WHERE vulnid=$2;",
		ssUpdateMitDate:    "UPDATE dates SET mitigated=$1 WHERE vulnid=$2;",
		ssUpdateMitigation: "UPDATE vuln SET mitigation=$1 WHERE vulnid=$2;",
		ssUpdatePubDate:    "UPDATE dates SET published=$1 WHERE vulnid=$2;",
		ssUpdateRefers:     "UPDATE ref SET url=$1 WHERE vulnid=$2 AND url=$3;",
		ssUpdateSummary:    "UPDATE vuln SET summary=$1 WHERE vulnid=$2;",
		ssUpdateSysName:    "UPDATE systems SET sysname=$1 WHERE sysid=$2;",
		ssUpdateSysType:    "UPDATE systems SET systype=$1 WHERE sysid=$2;",
		ssUpdateSysOS:      "UPDATE systems SET opsys=$1 WHERE sysid=$2;",
		ssUpdateSysLoc:     "UPDATE systems SET location=$1 WHERE sysid=$2;",
		ssUpdateSysDesc:    "UPDATE systems SET description=$1 WHERE sysid=$2;",
		ssUpdateSysState:   "UPDATE systems SET state=$1 WHERE sysid=$2;",
		ssUpdateTest:       "UPDATE vuln SET test=$1 WHERE vulnid=$2;",
		ssUpdateTicket:     "UPDATE tickets SET ticket=$1 WHERE vulnid=$2 AND ticket=$3;",
		ssUpdateVulnName:   "UPDATE vuln SET vulnname=$1 WHERE vulnid=$2;",
	}
	execNames = map[sqlStatement]string{
		ssGetExploit:       "GetExploit",
		ssGetReferences:    "GetReferences",
		ssGetSystem:        "GetSystem",
		ssGetSystems:       "GetSystems",
		ssGetSystemID:      "GetSystemID",
		ssGetTickets:       "GetTickets",
		ssGetVuln:          "GetVulnerability",
		ssInsertAffected:   "InsertAffected",
		ssInsertDates:      "InsertDates",
		ssInsertExploit:    "InsertExploit",
		ssInsertImpact:     "InsertImpact",
		ssInsertRefers:     "InsertRef",
		ssInsertTicket:     "InsertTicket",
		ssInsertVuln:       "InsertVulnerability",
		ssUpdateAffected:   "UpdateAffected",
		ssUpdateCve:        "UpdateCve",
		ssUpdateCvss:       "UpdateCvss",
		ssUpdateCvssLink:   "UpdateCvssLink",
		ssUpdateCorpScore:  "UpdateCorpScore",
		ssUpdateExploit:    "UpdateExploit",
		ssUpdateFinder:     "UpdateFinder",
		ssUpdateInitiator:  "UpdateInitiator",
		ssUpdateInitDate:   "UpdateInitDate",
		ssUpdateMitDate:    "UpdateMitDate",
		ssUpdateMitigation: "UpdateMitigation",
		ssUpdatePubDate:    "UpdatePubDate",
		ssUpdateRefers:     "UpdateRefers",
		ssUpdateSummary:    "UpdateSummary",
		ssUpdateSysName:    "UpdateSysName",
		ssUpdateSysType:    "UpdateSysType",
		ssUpdateSysOS:      "UpdateSysOS",
		ssUpdateSysLoc:     "UpdateSysLoc",
		ssUpdateSysDesc:    "UpdateSysDesc",
		ssUpdateSysState:   "UpdateSysState",
		ssUpdateTest:       "UpdateTest",
		ssUpdateTicket:     "UpdateTicket",
		ssUpdateVulnName:   "UpdateVulnName",
	}
)

// Employee holds information about an employee
type Employee struct {
	ID        int64
	FirstName string
	LastName  string
	Email     string
}

// System holds information about systems in the environment.
type System struct {
	ID          int64
	Name        string
	Type        string // Server, router, switch, etc
	OpSys       string
	Location    string // Corporate, hosted, etc
	Description string
	State       string // Active or decommissioned
}

// VulnDates holds the different dates relating to the vulnerability.
type VulnDates struct {
	Published VarsNullString // Date the vulnerability was made public
	Initiated string         // Date the vulnerability assessment was started
	Mitigated VarsNullString // Date the vulnerability was mitigated on all systems
}

// Vulnerability holds information about a discovered vulnerability and the vulnerability assessment.
type Vulnerability struct {
	ID          int64
	Name        string
	Cve         VarsNullString
	Cvss        float32        // CVSS score
	CorpScore   float32        // Calculated corporate score
	CvssLink    VarsNullString // Link to CVSS scoresheet
	Finder      int            // Employee that found the vulnerability
	Initiator   int            // Employee that started the vulnerability assessment
	Summary     string
	Test        string // Test to see if system has this vulnerability
	Mitigation  string
	Dates       VulnDates      // The dates associated with the vulnerability
	Tickets     []string       // Tickets relating to the vulnerability
	References  []string       // Reference URLs
	Exploit     VarsNullString // Exploit for the vulnerability
	Exploitable VarsNullBool   // Are there currently exploits for the vulnerability
}

// AddEmployee inserts a new employee into the VARS database.
func AddEmployee(db *sql.DB, emp *Employee) error {
	res, err := queries[ssInsertEmployee].Exec(emp.FirstName, emp.LastName, emp.Email)
	if rows, _ := res.RowsAffected(); rows < 1 {
		return newErr(noRowsInserted, "AddEmployee")
	}
	if err != nil {
		return newErrFromErr(err, "AddEmployee")
	}
	return nil
}

// GetExploit returns the row from the exploits table for the given vulnid.
func GetExploit(vid int64) (VarsNullString, VarsNullBool, error) {
	var exploit VarsNullString
	var exploitable VarsNullBool
	err := queries[ssGetExploit].QueryRow(vid).Scan(&exploitable, &exploit)
	if err != nil && err != sql.ErrNoRows {
		return exploit, exploitable, newErrFromErr(err, execNames[ssGetExploit])
	}
	return exploit, exploitable, nil
}

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems() (*[]System, error) {
	return execGetRowsSys(ssActiveSystems)
}

// GetReferences returns a pointer to a slice of urls associated with the vulnid.
func GetReferences(vid int64) (*[]string, error) {
	refs, err := execGetRowsStr(ssGetReferences, vid)
	if !IsNilErr(err) {
		var r []string
		return &r, newErrFromErr(err, execNames[ssGetReferences])
	}
	return refs, nil
}

// GetSystem returns a system struct matching the given systemID.
func GetSystem(sid int64) (*System, error) {
	var sys System
	sys.ID = sid
	err := queries[ssGetSystem].QueryRow(sid).Scan(&sys.Name, &sys.Type, &sys.OpSys, &sys.Location, &sys.Description, &sys.State)
	if err != nil && err != sql.ErrNoRows {
		return &sys, newErrFromErr(err, "GetSystem")
	}
	return &sys, nil
}

// GetSystems returns a pointer to a slice of System types representing all systems.
func GetSystems() (*[]System, error) {
	return execGetRowsSys(ssGetSystems)
}

// GetSystemID returns the sysid associated with the sysname.
func GetSystemID(sysname string) (int64, error) {
	var id int64
	err := queries[ssGetSystemID].QueryRow(sysname).Scan(&id)
	if err != nil {
		return id, newErrFromErr(err, "GetSystemID")
	}
	return id, nil
}

// GetSystemIDtx returns the sysid associated with the sysname.
func GetSystemIDtx(tx *sql.Tx, sysname string) (int64, error) {
	var id int64
	err := tx.Stmt(queries[ssGetSystemID]).QueryRow(sysname).Scan(&id)
	if err != nil {
		return id, newErrFromErr(err, "GetSystemIDtx")
	}
	return id, nil
}

// GetTickets returns a spointer to a lice of tickets associated with the vulnid.
func GetTickets(vid int64) (*[]string, error) {
	ticks, err := execGetRowsStr(ssGetTickets, vid)
	if !IsNilErr(err) {
		var t []string
		return &t, newErrFromErr(err, execNames[ssGetTickets])
	}
	return ticks, nil
}

// GetVulnerability returns a Vulnerability object for the given vulnid.
func GetVulnerability(vid int64) (*Vulnerability, error) {
	var vuln Vulnerability
	vuln.ID = vid
	err := queries[ssGetVuln].QueryRow(vid).Scan(&vuln.Name, &vuln.Cve, &vuln.Finder, &vuln.Initiator, &vuln.Summary, &vuln.Test, &vuln.Mitigation)
	if err != nil {
		return &vuln, newErrFromErr(err, execNames[ssGetVuln])
	}
	return &vuln, nil
}

// GetVulnerabilities returns a slice of pointers to Vulnerability objects. These objects will ONLY have the content from the vuln table
// in them. The id can then be passed into the other GetXYZ functions to retrieve the other parts of the vulnerability.
func GetVulnerabilities() ([]*Vulnerability, error) {
	vulns := []*Vulnerability{}
	rows, err := queries[ssGetVulns].Query()
	if err != nil {
		return vulns, newErrFromErr(err, "GetVulnerabilities")
	}
	defer rows.Close()
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.Name, &v.Cve, &v.Finder, &v.Initiator, &v.Summary, &v.Test, &v.Mitigation); err != nil {
			return vulns, newErrFromErr(err, "GetVulnerabilities", "row.Scan")
		}
		vulns = append(vulns, &v)
	}
	if err := rows.Err(); err != nil {
		return vulns, newErrFromErr(err, "GetVulnerabilities")
	}
	return vulns, nil
}

// GetVulnDates returns a VulnDates object with the dates row associated with the vulnid.
func GetVulnDates(vid int64) (*VulnDates, error) {
	var vd VulnDates
	err := queries[ssGetVulnDates].QueryRow(vid).Scan(&vd.Published, &vd.Initiated, &vd.Mitigated)
	if err != nil {
		return &vd, newErrFromErr(err, execNames[ssGetVulnDates])
	}
	return &vd, nil
}

// GetVulnID returns the vulnid associated with the vname.
func GetVulnID(vname string) (int64, error) {
	var id int64
	err := queries[ssGetVulnID].QueryRow(vname).Scan(&id)
	if err != nil {
		return id, newErrFromErr(err, "GetVulnID")
	}
	return id, nil
}

// GetVulnIDtx returns the vulnid associated with the vname.
func GetVulnIDtx(tx *sql.Tx, vulnname string) (int64, error) {
	var id int64
	err := tx.Stmt(queries[ssGetVulnID]).QueryRow(vulnname).Scan(&id)
	if err != nil {
		return id, newErrFromErr(err, "GetVulnIDtx")
	}
	return id, nil
}

// InsertAffected will insert a new row into the affected table with key (vid, sid).
func InsertAffected(tx *sql.Tx, vid, sid int64) Err {
	return execMutation(tx, ssInsertAffected, vid, sid)
}

// InsertDates inserts the dates published, initiated, and mitigated.
func InsertDates(tx *sql.Tx, vid int64, ini string, pub, mit VarsNullString) error {
	return execMutation(tx, ssInsertDates, vid, pub, ini, mit)
}

// InsertImpact inserts the CVSS score, Corpscore, and CVSSlink.
func InsertImpact(tx *sql.Tx, vid int64, cvss, corpscore float32, cvsslink VarsNullString) error {
	return execMutation(tx, ssInsertImpact, vid, cvss, cvsslink, corpscore)
}

// InsertRef will insert a new row into the ref table with key (vid, url).
func InsertRef(tx *sql.Tx, vid int64, url string) Err {
	return execMutation(tx, ssInsertRefers, vid, url)
}

// InsertSystem will add a new system to the database.
func InsertSystem(tx *sql.Tx, sys *System) Err {
	return execMutation(tx, ssInsertSystem, sys.Name, sys.Type, sys.OpSys, sys.Location, sys.Description, "active")
}

// InsertTicket will insert a new row into the ticket table with key (vid, ticket).
func InsertTicket(tx *sql.Tx, vid int64, ticket string) Err {
	return execMutation(tx, ssInsertTicket, vid, ticket)
}

// InsertVulnerability will insert a new row into the vuln table.
func InsertVulnerability(tx *sql.Tx, vname string, cve VarsNullString, finder, initiator int, summary, test, mitigation string) error {
	return execMutation(tx, ssInsertVuln, vname, cve, finder, initiator, summary, test, mitigation)
}

// IsVulnOpen returns true if the Vulnerability associated with the passed ID is still open,
// false otherwise.
func IsVulnOpen(vid int64) (bool, error) {
	vd, err := GetVulnDates(vid)
	if !IsNilErr(err) {
		return false, newErrFromErr(err, "IsVulnOpen")
	}
	if vd.Mitigated.Valid {
		return false, nil
	}
	return true, nil
}

// NameIsAvailable returns true if the vulnerability name is available, false otherwise.
func NameIsAvailable(obj interface{}) (bool, error) {
	var id int64
	var ss sqlStatement
	var name string

	// Get Type
	switch o := obj.(type) {
	case Vulnerability:
		ss = ssCheckVulnName
		name = o.Name
	case System:
		ss = ssCheckSysName
		name = o.Name
	default:
		return false, newErr(unknownType, "NameIsAvailable")
	}

	// Execute query
	err := queries[ss].QueryRow(name).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return true, nil
		}
		return false, newErrFromErr(err, "NameIsAvailable")
	}
	return false, nil
}

// SetExploit inserts an entry into the exploits table if the exploit string isn't zero valued.
func SetExploit(tx *sql.Tx, vuln *Vulnerability) error {
	var err Err
	if vuln.Exploit.Valid {
		err = execMutation(tx, ssInsertExploit, vuln.ID, true, vuln.Exploit.String)
	}
	return err
}

// SetReferences inserts entries into the ref table for all URLs in the slice.
func SetReferences(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if len(vuln.References) > 0 {
		for _, r := range vuln.References {
			err := InsertRef(tx, vuln.ID, r)
			if !IsNilErr(err) {
				if !err.IsNoRowsError() {
					return err
				}
				errs.appendFromError(err, "SetReferences")
			}
		}
	}
	return errs
}

// SetTickets inserts entries into the tickets table for all ticket ID's in the slice.
func SetTickets(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if len(vuln.Tickets) > 0 {
		for _, t := range vuln.Tickets {
			err := InsertTicket(tx, vuln.ID, t)
			if !IsNilErr(err) {
				if !err.IsNoRowsError() {
					return err
				}
				errs.appendFromError(err, "SetTickets")
			}
		}
	}
	return errs
}

// UpdateAffected will update the system ID associated with the (vid, oldSid) row to newSid.
func UpdateAffected(tx *sql.Tx, vid int64, oldSid, newSid int) Err {
	return execMutation(tx, ssUpdateAffected, newSid, vid, oldSid)
}

// UpdateCve will update the CVE for the given vulnerability ID.
func UpdateCve(tx *sql.Tx, vid int64, cve VarsNullString) Err {
	return execMutation(tx, ssUpdateCve, cve, vid)
}

// UpdateCvss will update the CVSS score for the given vulnerability ID.
func UpdateCvss(tx *sql.Tx, vid int64, cvss float32) Err {
	return execMutation(tx, ssUpdateCvss, cvss, vid)
}

// UpdateCvssLink will update the link to the CVSS score for the given vulnerability ID.
func UpdateCvssLink(tx *sql.Tx, vid int64, cvssLink VarsNullString) Err {
	return execMutation(tx, ssUpdateCvssLink, cvssLink, vid)
}

// UpdateCorpScore will update the corporate score for the given vulnerability ID.
func UpdateCorpScore(tx *sql.Tx, vid int64, cscore float32) Err {
	return execMutation(tx, ssUpdateCorpScore, cscore, vid)
}

// UpdateExploit will update the exploit and the exploitable column for the given vulnerability ID.
// To set the exploitable column to false and have a NULL value for the exploits column, pass in
// an empty string to exploit.
func UpdateExploit(tx *sql.Tx, vid int64, exploit string) Err {
	s := toNullString(exploit)
	return execMutation(tx, ssUpdateExploit, s.Valid, s, vid)
}

// UpdateFinder will update the finder for the given vulnerability ID.
func UpdateFinder(tx *sql.Tx, vid int64, finder int) Err {
	return execMutation(tx, ssUpdateFinder, finder, vid)
}

// UpdateInitiator will update the initiator for the given vulnerability ID.
func UpdateInitiator(tx *sql.Tx, vid int64, initiator int) Err {
	return execMutation(tx, ssUpdateInitiator, initiator, vid)
}

// UpdateInitDate will update the date that the vulnerability assessment was initiated for the given vulnerability ID.
func UpdateInitDate(tx *sql.Tx, vid int64, initDate string) Err {
	return execMutation(tx, ssUpdateInitDate, initDate, vid)
}

// UpdateMitDate will update the date that the vulnerability assessment was mitigated for the given vulnerability ID.
// To set the mitigation date to NULL, pass in an empty string for mitDate.
func UpdateMitDate(tx *sql.Tx, vid int64, mitDate VarsNullString) Err {
	return execMutation(tx, ssUpdateMitDate, mitDate, vid)
}

// UpdateMitigation will update the mitigation associated with the vulnerability ID.
func UpdateMitigation(tx *sql.Tx, vid int64, mit string) Err {
	return execMutation(tx, ssUpdateMitigation, mit, vid)
}

// UpdatePubDate will update the date that the vulnerability was published for the given vulnerability ID.
// To set the published date to NULL, pass in an empty string for pubDate.
func UpdatePubDate(tx *sql.Tx, vid int64, pubDate VarsNullString) Err {
	return execMutation(tx, ssUpdatePubDate, pubDate, vid)
}

// UpdateRefers will update the url associated with the (vid, oldURL) row to newURL.
func UpdateRefers(tx *sql.Tx, vid int64, oldURL, newURL string) Err {
	return execMutation(tx, ssUpdateRefers, newURL, vid, oldURL)
}

// UpdateSummary will update the summary associated with the vulnerability ID.
func UpdateSummary(tx *sql.Tx, vid int64, summary string) Err {
	return execMutation(tx, ssUpdateSummary, summary, vid)
}

// UpdateSysName will update the name associated with the sysid.
func UpdateSysName(tx *sql.Tx, sid int64, name string) Err {
	return execMutation(tx, ssUpdateSysName, name, sid)
}

// UpdateSysType will update the type associated with the sysid.
func UpdateSysType(tx *sql.Tx, sid int64, stype string) Err {
	return execMutation(tx, ssUpdateSysType, stype, sid)
}

// UpdateSysOS will update the OS associated with the sysid.
func UpdateSysOS(tx *sql.Tx, sid int64, os string) Err {
	return execMutation(tx, ssUpdateSysOS, os, sid)
}

// UpdateSysLoc will update the location associated with the sysid.
func UpdateSysLoc(tx *sql.Tx, sid int64, loc string) Err {
	return execMutation(tx, ssUpdateSysLoc, loc, sid)
}

// UpdateSysDesc will update the description associated with the sysid.
func UpdateSysDesc(tx *sql.Tx, sid int64, desc string) Err {
	return execMutation(tx, ssUpdateSysDesc, desc, sid)
}

// UpdateSysState will update the state associated with the sysid.
func UpdateSysState(tx *sql.Tx, sid int64, state string) Err {
	return execMutation(tx, ssUpdateSysState, state, sid)
}

// UpdateTicket will update the ticket associated with the (vid, oldTicket) row to newTicket.
func UpdateTicket(tx *sql.Tx, vid int64, oldTicket, newTicket string) Err {
	return execMutation(tx, ssUpdateTicket, newTicket, vid, oldTicket)
}

// UpdateTest will update the test associated with the vulnerability ID.
func UpdateTest(tx *sql.Tx, vid int64, test string) Err {
	return execMutation(tx, ssUpdateTest, test, vid)
}

// UpdateVulnName will update the vulnerability's name.
func UpdateVulnName(tx *sql.Tx, vid int64, vname string) Err {
	return execMutation(tx, ssUpdateVulnName, vname, vid)
}

// execMutation executes the query referenced by ss in the queries map and returns any errors.
func execMutation(tx *sql.Tx, ss sqlStatement, args ...interface{}) Err {
	var err Err
	res, e := tx.Stmt(queries[ss]).Exec(args...)
	if e != nil {
		return newErrFromErr(e, execNames[ss], "execMutation")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, execNames[ss], "execMutation")
	}
	return err
}

// execGetRowsStr executes the query referenced by ss in the queries map and returns a pointer to a slice of string and an error.
func execGetRowsStr(ss sqlStatement, args ...interface{}) (*[]string, error) {
	var res []string
	rows, err := queries[ss].Query(args...)
	if err != nil {
		return &res, newErrFromErr(err, execNames[ss], "execGetRowsStr")
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return &res, newErrFromErr(err, execNames[ss], "execGetRowsStr", "rows.Scan")
		}
		res = append(res, r)
	}
	if err := rows.Err(); err != nil {
		return &res, newErrFromErr(err, execNames[ss], "execGetRowsStr")
	}
	return &res, nil
}

// execGetRowsSys executes the query referenced by ss in the queries map and returns a pointer to a slice of System and an error.
func execGetRowsSys(ss sqlStatement, args ...interface{}) (*[]System, error) {
	res := []System{}
	rows, err := queries[ss].Query(args...)
	if err != nil {
		return &res, newErrFromErr(err, execNames[ss], "execGetRowsSys")
	}
	defer rows.Close()
	for rows.Next() {
		var r System
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.OpSys, &r.Location, &r.Description); err != nil {
			return &res, newErrFromErr(err, execNames[ss], "execGetRowsSys", "rows.Scan")
		}
		res = append(res, r)
	}
	if err := rows.Err(); err != nil {
		return &res, newErrFromErr(err, execNames[ss], "execGetRowsSys")
	}
	return &res, nil
}
