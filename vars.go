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
	execNames = map[sqlStatement]string{
		ssInsertExploit:   "InsertExploit",
		ssInsertRefers:    "InsertRef",
		ssInsertTicket:    "InsertTicket",
		ssUpdateCve:       "UpdateCve",
		ssUpdateCvss:      "UpdateCvss",
		ssUpdateCvssLink:  "UpdateCvssLink",
		ssUpdateCorpScore: "UpdateCorpScore",
		ssUpdateInitDate:  "UpdateInitDate",
		ssUpdateMitDate:   "UpdateMitDate",
		ssUpdatePubDate:   "UpdatePubDate",
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

// VulnDates holds the different dates relating to the vulnerability.
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
		errs.appendFromError(ve, "AddVulnerability")
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the dates table
	e = SetDates(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve, "AddVulnerability")
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the tickets table
	e = SetTickets(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve, "AddVulnerability")
	} else if ves, ok := e.(Errs); ok {
		errs.appendFromErrs(ves)
	}

	// Setting values in the ref table
	e = SetReferences(tx, vuln)
	if ve, ok := e.(Err); ok {
		if !ve.IsNoRowsError() {
			return ve
		}
		errs.appendFromError(ve, "AddVulnerability")
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
			errs.appendFromError(err, "SetImpact")
		}
	}
	if vuln.CvssLink.Valid {
		err := UpdateCvssLink(tx, vuln.ID, vuln.CvssLink.String)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err, "SetImpact")
		}
	}
	if vuln.CorpScore != 0 {
		err := UpdateCorpScore(tx, vuln.ID, vuln.CorpScore)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err, "SetImpact")
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
			errs.appendFromError(err, "SetDates")
		}
	}
	if vuln.Dates.Initiated != "" {
		err := UpdateInitDate(tx, vuln.ID, vuln.Dates.Initiated)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err, "SetDates")
		}
	}
	if vuln.Dates.Mitigated.Valid {
		err := UpdateMitDate(tx, vuln.ID, vuln.Dates.Mitigated.String)
		if err.err != nil {
			if !err.IsNoRowsError() {
				return err
			}
			errs.appendFromError(err, "SetDates")
		}
	}
	return errs
}

// SetExploit inserts an entry into the exploits table if the exploit string isn't zero valued.
func SetExploit(tx *sql.Tx, vuln *Vulnerability) error {
	var err Err
	if vuln.Exploit.Valid {
		err = execUpdates(tx, ssInsertExploit, vuln.ID, true, vuln.Exploit.String)
	}
	return err
}

// SetReferences inserts entries into the ref table for all URLs in the slice.
func SetReferences(tx *sql.Tx, vuln *Vulnerability) error {
	var errs Errs
	if len(vuln.References) > 0 {
		for _, r := range vuln.References {
			err := execUpdates(tx, ssInsertRefers, vuln.ID, r)
			if err.err != nil {
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
			err := execUpdates(tx, ssInsertTicket, vuln.ID, t)
			if err.err != nil {
				if !err.IsNoRowsError() {
					return err
				}
				errs.appendFromError(err, "SetTickets")
			}
		}
	}
	return errs
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
	return execUpdates(tx, ssUpdateCve, cve, vid)
}

// UpdateCvss will update the CVSS score for the given vulnerability ID.
func UpdateCvss(tx *sql.Tx, vid int, cvss float32) Err {
	return execUpdates(tx, ssUpdateCvss, cvss, vid)
}

// UpdateCvssLink will update the link to the CVSS score for the given vulnerability ID.
func UpdateCvssLink(tx *sql.Tx, vid int, cvssLink string) Err {
	return execUpdates(tx, ssUpdateCvssLink, cvssLink, vid)
}

// UpdateCorpScore will update the corporate score for the given vulnerability ID.
func UpdateCorpScore(tx *sql.Tx, vid int, cscore float32) Err {
	return execUpdates(tx, ssUpdateCorpScore, cscore, vid)
}

// UpdateInitDate will update the date that the vulnerability assessment was initiated for the given vulnerability ID.
func UpdateInitDate(tx *sql.Tx, vid int, initDate string) Err {
	return execUpdates(tx, ssUpdateInitDate, initDate, vid)
}

// UpdateMitDate will update the date that the vulnerability assessment was mitigated for the given vulnerability ID.
func UpdateMitDate(tx *sql.Tx, vid int, mitDate string) Err {
	return execUpdates(tx, ssUpdateMitDate, mitDate, vid)
}

// UpdatePubDate will update the date that the vulnerability was published for the given vulnerability ID.
func UpdatePubDate(tx *sql.Tx, vid int, pubDate string) Err {
	return execUpdates(tx, ssUpdatePubDate, pubDate, vid)
}

func execUpdates(tx *sql.Tx, ss sqlStatement, args ...interface{}) Err {
	var err Err
	res, e := tx.Stmt(queries[ss]).Exec(args)
	if e != nil {
		return newErrFromErr(e, execNames[ss])
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, execNames[ss])
	}
	return err
}
