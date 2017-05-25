// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
	"database/sql"

	_ "github.com/lib/pq" // Postgresql driver
)

type sqlStatement int

const (
	ssActiveSystems sqlStatement = iota
	ssCheckName
	ssDecomSystem
	ssGetExploit
	ssGetReferences
	ssGetSystems
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
	ssUpdateInitDate
	ssUpdateMitDate
	ssUpdatePubDate
	ssUpdateRefers
	ssUpdateTicket
)

// SQL queries to be used in program execution.
var (
	queries      map[sqlStatement]*sql.Stmt
	queryStrings = map[sqlStatement]string{
		ssActiveSystems:   "SELECT sysid, sysname, systype, opsys, location, description FROM systems WHERE state='active';",
		ssCheckName:       "SELECT vulnid FROM vuln WHERE vulnname=$1;",
		ssDecomSystem:     "UPDATE systems SET state='decommissioned' WHERE sysname=$1;",
		ssGetExploit:      "SELECT exploitable, exploit FROM exploits WHERE vulnid=$1;",
		ssGetReferences:   "SELECT url FROM ref WHERE vulnid=$1;",
		ssGetSystems:      "SELECT sysid, sysname, systype, opsys, location, description, state FROM systems;",
		ssGetTickets:      "SELECT ticket FROM tickets WHERE vulnid=$1;",
		ssGetVuln:         "SELECT cve, finder, initiator, summary, test, mitigation FROM vuln WHERE vulnid=$1;",
		ssGetVulns:        "SELECT vulnid, vulnname, cve, finder, initiator, summary, test, mitigation FROM vuln;",
		ssGetVulnDates:    "SELECT published, initiated, mitigated FROM dates WHERE vulnid=$1;",
		ssGetVulnID:       "SELECT vulnid FROM vuln WHERE vulnname=$1;",
		ssInsertAffected:  "INSERT INTO affected (vulnid, sysid) VALUES ($1, $2);",
		ssInsertDates:     "INSERT INTO dates (vulnid, published, initiated, mitigated) VALUES ($1, $2, $3, $4);",
		ssInsertEmployee:  "INSERT INTO emp (firstname, lastname, email) VALUES ($1, $2, $3);",
		ssInsertExploit:   "INSERT INTO exploits (vulnid, exploitable, exploit) VALUES ($1, $2, $3);",
		ssInsertImpact:    "INSERT INTO impact (vulnid, cvss, cvsslink, corpscore) VALUES ($1, $2, $3, $4);",
		ssInsertRefers:    "INSERT INTO ref (vulnid, url) VALUES ($1, $2);",
		ssInsertSystem:    "INSERT INTO systems (sysname, systype, opsys, location, description, state) VALUES ($1, $2, $3, $4, $5, $6);",
		ssInsertTicket:    "INSERT INTO tickets (vulnid, ticket) VALUES ($1, $2);",
		ssInsertVuln:      "INSERT INTO vuln (vulnname, cve, finder, initiator, summary, test, mitigation) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING vulnid;",
		ssUpdateAffected:  "UPDATE affected SET sysid=$1 WHERE vulnid=$2 AND sysid=$3;",
		ssUpdateCve:       "UPDATE vuln SET cve=$1 WHERE vulnid=$2;",
		ssUpdateCvss:      "UPDATE impact SET cvss=$1 WHERE vulnid=$2;",
		ssUpdateCvssLink:  "UPDATE impact SET cvsslink=$1 WHERE vulnid=$2;",
		ssUpdateCorpScore: "UPDATE impact SET corpscore=$1 WHERE vulnid=$2;",
		ssUpdateExploit:   "UPDATE exploits SET exploitable=$1, exploit=$2 WHERE vulnid=$3;",
		ssUpdateInitDate:  "UPDATE dates SET initiated=$1 WHERE vulnid=$2;",
		ssUpdateMitDate:   "UPDATE dates SET mitigated=$1 WHERE vulnid=$2;",
		ssUpdatePubDate:   "UPDATE dates SET published=$1 WHERE vulnid=$2;",
		ssUpdateRefers:    "UPDATE ref SET url=$1 WHERE vulnid=$2 AND url=$3;",
		ssUpdateTicket:    "UPDATE tickets SET ticket=$1 WHERE vulnid=$2 AND ticket=$3;",
	}
	execNames = map[sqlStatement]string{
		ssGetExploit:      "GetExploit",
		ssGetReferences:   "GetReferences",
		ssGetSystems:      "GetSystems",
		ssGetTickets:      "GetTickets",
		ssInsertAffected:  "InsertAffected",
		ssInsertDates:     "InsertDates",
		ssInsertExploit:   "InsertExploit",
		ssInsertImpact:    "InsertImpact",
		ssInsertRefers:    "InsertRef",
		ssInsertTicket:    "InsertTicket",
		ssInsertVuln:      "InsertVulnerability",
		ssUpdateAffected:  "UpdateAffected",
		ssUpdateCve:       "UpdateCve",
		ssUpdateCvss:      "UpdateCvss",
		ssUpdateCvssLink:  "UpdateCvssLink",
		ssUpdateCorpScore: "UpdateCorpScore",
		ssUpdateExploit:   "UpdateExploit",
		ssUpdateInitDate:  "UpdateInitDate",
		ssUpdateMitDate:   "UpdateMitDate",
		ssUpdatePubDate:   "UpdatePubDate",
		ssUpdateRefers:    "UpdateRefers",
		ssUpdateTicket:    "UpdateTicket",
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
	Published sql.NullString // Date the vulnerability was made public
	Initiated string         // Date the vulnerability assessment was started
	Mitigated sql.NullString // Date the vulnerability was mitigated on all systems
}

// Vulnerability holds information about a discovered vulnerability and the vulnerability assessment.
type Vulnerability struct {
	ID          int64
	Name        string
	Cve         sql.NullString
	Cvss        float32        // CVSS score
	CorpScore   float32        // Calculated corporate score
	CvssLink    sql.NullString // Link to CVSS scoresheet
	Finder      int            // Employee that found the vulnerability
	Initiator   int            // Employee that started the vulnerability assessment
	Summary     string
	Test        string // Test to see if system has this vulnerability
	Mitigation  string
	Dates       VulnDates      // The dates associated with the vulnerability
	Tickets     []string       // Tickets relating to the vulnerability
	References  []string       // Reference URLs
	Exploit     sql.NullString // Exploit for the vulnerability
	Exploitable sql.NullBool   // Are there currently exploits for the vulnerability
}

// AddSystem inserts a new systems into the VARS database.
func AddSystem(db *sql.DB, sys *System) error {
	res, err := queries[ssInsertSystem].Exec(sys.Name, sys.Type, sys.OpSys, sys.Location, sys.Description, "active")
	if rows, _ := res.RowsAffected(); rows < 1 {
		return newErr(noRowsInserted, "AddSystem")
	}
	if err != nil {
		return newErrFromErr(err, "AddSystem")
	}
	return nil
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

// AddVulnerability starts a new vulnerability assessment by inserting a new vulnerability.
func AddVulnerability(db *sql.DB, vuln *Vulnerability) error {
	var errs Errs

	// Check if vulnerability name is available
	a, er := NameIsAvailable(vuln.Name)
	if er != nil {
		return newErrFromErr(er, "AddVulnerability")
	}
	if !a {
		return newErr(nameNotAvailable, "AddVulnerability")
	}

	// Setting values in the vuln table
	var id int64
	err := queries[ssInsertVuln].QueryRow(vuln.Name, vuln.Cve, vuln.Finder, vuln.Initiator, vuln.Summary, vuln.Test, vuln.Mitigation).Scan(&id)
	if err != nil {
		return newErrFromErr(err, "AddVulnerability", "ssInsertVuln")
	}
	vuln.ID = id

	tx, err := db.Begin()
	if err != nil {
		return newErrFromErr(err, "AddVulnerability")
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	var e interface{}

	// Setting values in the impact table
	e = InsertImpact(tx, vuln.ID, vuln.Cvss, vuln.CorpScore, vuln.CvssLink)
	if ve, ok := e.(Err); ok {
		if !IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
			errs.appendFromError(ve, "AddVulnerability")
		}
	} else if ves, ok := e.(Errs); ok {
		if !IsNilErr(ves) {
			errs.appendFromErrs(ves)
		}
	}

	// Setting values in the dates table
	e = InsertDates(tx, vuln.ID, vuln.Dates.Initiated, vuln.Dates.Published, vuln.Dates.Mitigated)
	if ve, ok := e.(Err); ok {
		if !IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
			errs.appendFromError(ve, "AddVulnerability")
		}
	} else if ves, ok := e.(Errs); ok {
		if !IsNilErr(ves) {
			errs.appendFromErrs(ves)
		}
	}

	// Setting values in the tickets table
	e = SetTickets(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
			errs.appendFromError(ve, "AddVulnerability")
		}
	} else if ves, ok := e.(Errs); ok {
		if !IsNilErr(ves) {
			errs.appendFromErrs(ves)
		}
	}

	// Setting values in the ref table
	e = SetReferences(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
			errs.appendFromError(ve, "AddVulnerability")
		}
	} else if ves, ok := e.(Errs); ok {
		if !IsNilErr(ves) {
			errs.appendFromErrs(ves)
		}
	}

	// Setting values in the exploits table
	e = SetExploit(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !IsNilErr(ve) {
			if !ve.IsNoRowsError() {
				return ve
			}
			errs.appendFromError(ve, "AddVulnerability")
		}
	} else if ves, ok := e.(Errs); ok {
		if !IsNilErr(ves) {
			errs.appendFromErrs(ves)
		}
	}

	rollback = false
	if e := tx.Commit(); e != nil {
		errs.appendFromError(e, "AddVulnerability")
	}
	return errs
}

// DecommissionSystem updates the system table to reflect a decommissioned system.
func DecommissionSystem(db *sql.DB, name string) error {
	res, err := queries[ssDecomSystem].Exec(name)
	if rows, _ := res.RowsAffected(); rows < 1 {
		return newErr(noRowsUpdated, "DecommissionSystem")
	}
	if err != nil {
		return newErrFromErr(err, "DecommissionSystem")
	}
	return nil
}

// GetExploit returns the row from the exploits table for the given vulnid.
func GetExploit(vid int64) (sql.NullString, sql.NullBool, error) {
	var exploit sql.NullString
	var exploitable sql.NullBool
	err := queries[ssGetExploit].QueryRow(vid).Scan(&exploitable, &exploit)
	if err != nil && err != sql.ErrNoRows {
		return exploit, exploitable, newErrFromErr(err, "GetExploit")
	}
	return exploit, exploitable, nil
}

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems() (*[]System, error) {
	return execGetRowsSys(ssActiveSystems)
}

// GetReferences returns a pointer to a slice of urls associated with the vulnid.
func GetReferences(vid int64) (*[]string, error) {
	return execGetRowsStr(ssGetReferences, vid)
}

// GetSystems returns a pointer to a slice of System types representing all systems.
func GetSystems() (*[]System, error) {
	return execGetRowsSys(ssGetSystems)
}

// GetTickets returns a spointer to a lice of tickets associated with the vulnid.
func GetTickets(vid int64) (*[]string, error) {
	return execGetRowsStr(ssGetTickets, vid)
}

// GetVulnerability returns a Vulnerability object for the given vulnname.
func GetVulnerability(vname string) (*Vulnerability, error) {
	var vuln Vulnerability

	// Get vulnid
	id, err := GetVulnID(vname)
	if !IsNilErr(err) {
		return &vuln, err
	}
	vuln.ID = id
	vuln.Name = vname

	// Get vuln fields
	err = queries[ssGetVuln].QueryRow(id).Scan(&vuln.Cve, &vuln.Finder, &vuln.Initiator, &vuln.Summary, &vuln.Test, &vuln.Mitigation)
	if err != nil {
		return &vuln, newErrFromErr(err, "GetVulnerability")
	}

	// Get dates
	vd, err := GetVulnDates(id)
	if !IsNilErr(err) {
		return &vuln, newErrFromErr(err, "GetVulnerability")
	}
	vuln.Dates = *vd

	// Get tickets
	ticks, err := GetTickets(id)
	if !IsNilErr(err) {
		return &vuln, newErrFromErr(err, "GetVulnerability")
	}
	vuln.Tickets = *ticks

	// Get references
	refs, err := GetReferences(id)
	if !IsNilErr(err) {
		return &vuln, newErrFromErr(err, "GetVulnerability")
	}
	vuln.References = *refs

	// Get exploit
	exploit, exploitable, err := GetExploit(id)
	if !IsNilErr(err) {
		return &vuln, newErrFromErr(err, "GetVulnerability")
	}
	vuln.Exploit = exploit
	vuln.Exploitable = exploitable

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
		return &vd, newErrFromErr(err, "GetVulnDates")
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

// InsertAffected will insert a new row into the affected table with key (vid, sid).
func InsertAffected(tx *sql.Tx, vid int64, sid int) Err {
	return execMutation(tx, ssInsertAffected, vid, sid)
}

// InsertDates inserts the dates published, initiated, and mitigated.
func InsertDates(tx *sql.Tx, vid int64, ini string, pub, mit sql.NullString) error {
	return execMutation(tx, ssInsertDates, vid, pub, ini, mit)
}

// InsertImpact inserts the dates published, initiated, and mitigated.
func InsertImpact(tx *sql.Tx, vid int64, cvss, corpscore float32, cvsslink sql.NullString) error {
	return execMutation(tx, ssInsertImpact, vid, cvss, cvsslink, corpscore)
}

// InsertRef will insert a new row into the ref table with key (vid, url).
func InsertRef(tx *sql.Tx, vid int64, url string) Err {
	return execMutation(tx, ssInsertRefers, vid, url)
}

// InsertTicket will insert a new row into the ticket table with key (vid, ticket).
func InsertTicket(tx *sql.Tx, vid int64, ticket string) Err {
	return execMutation(tx, ssInsertTicket, vid, ticket)
}

// InsertVulnerability will insert a new row into the vuln table.
func InsertVulnerability(tx *sql.Tx, vname, cve string, finder, initiator int, summary, test, mitigation string) error {
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
func NameIsAvailable(vname string) (bool, error) {
	var vid int64
	err := queries[ssCheckName].QueryRow(vname).Scan(&vid)
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
func UpdateCve(tx *sql.Tx, vid int64, cve string) Err {
	return execMutation(tx, ssUpdateCve, cve, vid)
}

// UpdateCvss will update the CVSS score for the given vulnerability ID.
func UpdateCvss(tx *sql.Tx, vid int64, cvss float32) Err {
	return execMutation(tx, ssUpdateCvss, cvss, vid)
}

// UpdateCvssLink will update the link to the CVSS score for the given vulnerability ID.
func UpdateCvssLink(tx *sql.Tx, vid int64, cvssLink string) Err {
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

// UpdateInitDate will update the date that the vulnerability assessment was initiated for the given vulnerability ID.
func UpdateInitDate(tx *sql.Tx, vid int64, initDate string) Err {
	return execMutation(tx, ssUpdateInitDate, initDate, vid)
}

// UpdateMitDate will update the date that the vulnerability assessment was mitigated for the given vulnerability ID.
// To set the mitigation date to NULL, pass in an empty string for mitDate.
func UpdateMitDate(tx *sql.Tx, vid int64, mitDate string) Err {
	s := toNullString(mitDate)
	return execMutation(tx, ssUpdateMitDate, s, vid)
}

// UpdatePubDate will update the date that the vulnerability was published for the given vulnerability ID.
// To set the published date to NULL, pass in an empty string for pubDate.
func UpdatePubDate(tx *sql.Tx, vid int64, pubDate string) Err {
	s := toNullString(pubDate)
	return execMutation(tx, ssUpdatePubDate, s, vid)
}

// UpdateRefers will update the url associated with the (vid, oldURL) row to newURL.
func UpdateRefers(tx *sql.Tx, vid int64, oldURL, newURL string) Err {
	return execMutation(tx, ssUpdateRefers, newURL, vid, oldURL)
}

// UpdateTicket will update the ticket associated with the (vid, oldTicket) row to newTicket.
func UpdateTicket(tx *sql.Tx, vid int64, oldTicket, newTicket string) Err {
	return execMutation(tx, ssUpdateTicket, newTicket, vid, oldTicket)
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
