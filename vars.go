// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
	"database/sql"

	_ "github.com/lib/pq" // Postgresql driver
)

type sqlStatement int

const (
	ssActiveSystems sqlStatement = iota
	ssDecomSystem
	ssGetVulnDates
	ssInsertExploit
	ssInsertRefers
	ssInsertSystem
	ssInsertTicket
	ssInsertVuln
	ssUpdateCve
	ssUpdateCvss
	ssUpdateCvssLink
	ssUpdateCorpScore
	ssUpdateInitDate
	ssUpdateMitDate
	ssUpdatePubDate
)

// SQL queries to be used in program execution.
var (
	queries      map[sqlStatement]*sql.Stmt
	queryStrings = map[sqlStatement]string{
		ssActiveSystems:   "SELECT sysid, sysname, systype, opsys, location, description FROM systems WHERE state='active';",
		ssDecomSystem:     "UPDATE systems SET state='decommissioned' WHERE sysname=$1;",
		ssGetVulnDates:    "SELECT published, initiated, mitigated FROM dates WHERE vulnid=$1;",
		ssInsertExploit:   "INSERT INTO exploits (vulnid, exploitable, exploit) VALUES ($1, $2, $3);",
		ssInsertRefers:    "INSERT INTO ref (vulnid, url) VALUES ($1, $2);",
		ssInsertSystem:    "INSERT INTO systems (sysname, systype, opsys, location, description, state) VALUES ($1, $2, $3, $4, $5, $6);",
		ssInsertTicket:    "INSERT INTO tickets (vulnid, ticket) VALUES ($1, $2);",
		ssInsertVuln:      "INSERT INTO vuln (vulnname, cve, finder, initiator, summary, test, mitigation) VALUES ($1, $2, $3, $4, $5, $6, $7);",
		ssUpdateCve:       "UPDATE vuln SET cve=$1 WHERE vulnid=$2;",
		ssUpdateCvss:      "UPDATE impact SET cvss=$1 WHERE vulnid=$2;",
		ssUpdateCvssLink:  "UPDATE impact SET cvsslink=$1 WHERE vulnid=$2;",
		ssUpdateCorpScore: "UPDATE impact SET corpscore=$1 WHERE vulnid=$2;",
		ssUpdateInitDate:  "UPDATE dates SET initiated=$1 WHERE vulnid=$2;",
		ssUpdateMitDate:   "UPDATE dates SET mitigated=$1 WHERE vulnid=$2;",
		ssUpdatePubDate:   "UPDATE dates SET published=$1 WHERE vulnid=$2;",
	}
)

// Employee holds information about an employee
type Employee struct {
	ID        int
	FirstName string
	LastName  string
	Email     string
}

// System holds information about systems in the environment.
type System struct {
	ID          int
	Name        string
	Type        string // Server, router, switch, etc
	OpSys       string
	Location    string // Corporate, hosted, etc
	Description string
	State       string // Active or decommissioned
}

type VulnDates struct {
	Published sql.NullString // Date the vulnerability was made public
	Initiated string         // Date the vulnerability assessment was started
	Mitigated sql.NullString // Date the vulnerability was mitigated on all systems
}

// Vulnerability holds information about a discovered vulnerability and the vulnerability assessment.
type Vulnerability struct {
	ID          int
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
	return err
}

// AddVulnerability starts a new vulnerability assessment by inserting a new vulnerability.
func AddVulnerability(db *sql.DB, vuln *Vulnerability) error {
	var errs Errs
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
	res, err := tx.Stmt(queries[ssInsertVuln]).Exec(vuln.Name, vuln.Cve, vuln.Finder, vuln.Initiator, vuln.Summary, vuln.Test, vuln.Mitigation)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		errs.append(noRowsInserted, "AddVulnerability")
	}

	var e interface{}
	// Setting values in the impact table
	e = SetImpact(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve.err, append([]string{"AddVulnerability"}, ve.parents...)...)
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the dates table
	e = SetDates(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve.err, append([]string{"AddVulnerability"}, ve.parents...)...)
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the tickets table
	e = SetTickets(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve.err, append([]string{"AddVulnerability"}, ve.parents...)...)
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the ref table
	e = SetReferences(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve.err, append([]string{"AddVulnerability"}, ve.parents...)...)
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
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
	return err
}

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems(db *sql.DB) (*[]System, error) {
	systems := []System{}
	rows, err := queries[ssActiveSystems].Query()
	if err != nil {
		return &systems, err
	}
	defer rows.Close()
	for rows.Next() {
		var sys System
		if err := rows.Scan(&sys.ID, &sys.Name, &sys.Type, &sys.OpSys, &sys.Location, &sys.Description); err != nil {
			return &systems, err
		}
		systems = append(systems, sys)
	}
	if err := rows.Err(); err != nil {
		return &systems, err
	}
	return &systems, nil
}

// SetImpact updates the CVSS score and links and the Corporate Risk Score for a vulnerability.
// It will not do a partial update as in if something fails, the transaction is rolled back.
func SetImpact(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if vuln.Cvss != 0 {
		err := UpdateCvss(tx, vuln.ID, vuln.Cvss)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetImpact"}, err.parents...)...)
		}
	}
	if vuln.CvssLink.Valid {
		err := UpdateCvssLink(tx, vuln.ID, vuln.CvssLink.String)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetImpact"}, err.parents...)...)
		}
	}
	if vuln.CorpScore != 0 {
		err := UpdateCorpScore(tx, vuln.ID, vuln.CorpScore)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetImpact"}, err.parents...)...)
		}
	}
	return errs
}

// SetDates updates the dates published, initiated, and mitigated.
func SetDates(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if vuln.Dates.Published.Valid {
		err := UpdatePubDate(tx, vuln.ID, vuln.Dates.Published.String)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetDates"}, err.parents...)...)
		}
	}
	if vuln.Dates.Initiated != "" {
		err := UpdateInitDate(tx, vuln.ID, vuln.Dates.Initiated)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetDates"}, err.parents...)...)
		}
	}
	if vuln.Dates.Mitigated.Valid {
		err := UpdateMitDate(tx, vuln.ID, vuln.Dates.Mitigated.String)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err.err, append([]string{"SetDates"}, err.parents...)...)
		}
	}
	return errs
}

// SetExploit inserts an entry into the exploits table if the exploit string isn't zero valued.
func SetExploit(tx *sql.Tx, vuln *Vulnerability) error {
	var err Err
	if vuln.Exploit.Valid {
		err = InsertExploit(tx, vuln.ID, vuln.Exploit.String)
	}
	return err
}

// SetReferences inserts entries into the ref table for all URLs in the slice.
func SetReferences(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if len(vuln.References) > 0 {
		for _, r := range vuln.References {
			err := InsertRef(tx, vuln.ID, r)
			if err.err != nil {
				if !err.IsNoRowsError() {
					return err
				}
				errs.appendFromError(err.err, append([]string{"SetReferences"}, err.parents...)...)
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
			if err.err != nil {
				if !err.IsNoRowsError() {
					return err
				}
				errs.appendFromError(err.err, append([]string{"SetTickets"}, err.parents...)...)
			}
		}
	}
	return errs
}

// InsertExploit will update the ref table with the given url and vulnerability ID.
func InsertExploit(tx *sql.Tx, vid int, exp string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssInsertExploit]).Exec(vid, true, exp)
	if e != nil {
		return newErrFromErr(e, "InsertExploit")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "InsertExploit")
	}
	return err
}

// InsertRef will update the ref table with the given url and vulnerability ID.
func InsertRef(tx *sql.Tx, vid int, url string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssInsertRefers]).Exec(vid, url)
	if e != nil {
		return newErrFromErr(e, "InsertRef")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "InsertRef")
	}
	return err
}

// InsertTicket will update the tickets table with the given ticket and vulnerability ID.
func InsertTicket(tx *sql.Tx, vid int, tick string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssInsertTicket]).Exec(vid, tick)
	if e != nil {
		return newErrFromErr(e, "InsertTicket")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "InsertTicket")
	}
	return err
}

// IsVulnOpen returns true if the Vulnerability associated with the passed ID is still open,
// false otherwise.
func IsVulnOpen(db *sql.DB, vid int) (bool, error) {
	var vd VulnDates
	err := queries[ssGetVulnDates].QueryRow(vid).Scan(&vd.Published, &vd.Initiated, &vd.Mitigated)
	if err != nil {
		return false, err
	}
	if vd.Mitigated.Valid {
		return false, nil
	}
	return true, nil
}

// UpdateCve will update the CVE for the given vulnerability ID.
func UpdateCve(tx *sql.Tx, vid int, cve string) error {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateCve]).Exec(cve, vid)
	if e != nil {
		return e
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateCve")
	}
	return err
}

// UpdateCvss will update the CVSS score for the given vulnerability ID.
func UpdateCvss(tx *sql.Tx, vid int, cvss float32) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateCvss]).Exec(cvss, vid)
	if e != nil {
		return newErrFromErr(e, "UpdateCvss")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateCvss")
	}
	return err
}

// UpdateCvssLink will update the link to the CVSS score for the given vulnerability ID.
func UpdateCvssLink(tx *sql.Tx, vid int, cvssLink string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateCvssLink]).Exec(cvssLink, vid)
	if e != nil {
		return newErrFromErr(e, "UpdateCvssLink")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateCvssLink")
	}
	return err
}

// UpdateCorpScore will update the corporate score for the given vulnerability ID.
func UpdateCorpScore(tx *sql.Tx, vid int, cscore float32) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateCorpScore]).Exec(cscore, vid)
	if e != nil {
		return newErrFromErr(e, "UpdateCorpScore")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateCorpScore")
	}
	return err
}

// UpdateInitDate will update the date that the vulnerability assessment was initiated for the given vulnerability ID.
func UpdateInitDate(tx *sql.Tx, vid int, initDate string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateInitDate]).Exec(initDate, vid)
	if e != nil {
		return newErrFromErr(e, "UpdateInitDate")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateInitDate")
	}
	return err
}

// UpdateMitDate will update the date that the vulnerability assessment was mitigated for the given vulnerability ID.
func UpdateMitDate(tx *sql.Tx, vid int, mitDate string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdateMitDate]).Exec(mitDate, vid)
	if e != nil {
		return newErrFromErr(e, "UpdateMitDate")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdateMitDate")
	}
	return err
}

// UpdatePubDate will update the date that the vulnerability was published for the given vulnerability ID.
func UpdatePubDate(tx *sql.Tx, vid int, pubDate string) Err {
	var err Err
	res, e := tx.Stmt(queries[ssUpdatePubDate]).Exec(pubDate, vid)
	if e != nil {
		return newErrFromErr(e, "UpdatePubDate")
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, "UpdatePubDate")
	}
	return err
}
