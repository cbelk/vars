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
	ssGetVulnDates
	ssGetVulnId
	ssInsertAffected
	ssInsertEmployee
	ssInsertExploit
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
		ssGetVulnDates:    "SELECT published, initiated, mitigated FROM dates WHERE vulnid=$1;",
		ssGetVulnId:       "SELECT vulnid FROM vuln WHERE vulnname=$1;",
		ssInsertAffected:  "INSERT INTO affected (vulnid, sysid) VALUES ($1, $2);",
		ssInsertEmployee:  "INSERT INTO emp (firstname, lastname, email) VALUES ($1, $2, $3);",
		ssInsertExploit:   "INSERT INTO exploits (vulnid, exploitable, exploit) VALUES ($1, $2, $3);",
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
		ssInsertAffected:  "InsertAffected",
		ssInsertExploit:   "InsertExploit",
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
	if err != nil {
		return newErrFromErr(err, "DecommissionSystem")
	}
	return nil
}

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems() (*[]System, error) {
	systems := []System{}
	rows, err := queries[ssActiveSystems].Query()
	if err != nil {
		return &systems, newErrFromErr(err, "GetActiveSystems")
	}
	defer rows.Close()
	for rows.Next() {
		var sys System
		if err := rows.Scan(&sys.ID, &sys.Name, &sys.Type, &sys.OpSys, &sys.Location, &sys.Description); err != nil {
			return &systems, newErrFromErr(err, "GetActiveSystems", "rows.Scan")
		}
		systems = append(systems, sys)
	}
	if err := rows.Err(); err != nil {
		return &systems, newErrFromErr(err, "GetActiveSystems")
	}
	return &systems, nil
}

func GetVulnId(vname string) (int64, error) {
	var id int64
	err := queries[ssGetVulnId].QueryRow(vname).Scan(&id)
	if err != nil {
		return id, newErrFromErr(err, "GetVulnId")
	}
	return id, nil
}

// InsertAffected will insert a new row into the affected table with key (vid, sid).
func InsertAffected(tx *sql.Tx, vid int64, sid int) Err {
	return execUpdates(tx, ssInsertAffected, vid, sid)
}

// InsertRef will insert a new row into the ref table with key (vid, url).
func InsertRef(tx *sql.Tx, vid int64, url string) Err {
	return execUpdates(tx, ssInsertRefers, vid, url)
}

// InsertTicket will insert a new row into the ticket table with key (vid, ticket).
func InsertTicket(tx *sql.Tx, vid int64, ticket string) Err {
	return execUpdates(tx, ssInsertTicket, vid, ticket)
}

func InsertVulnerability(tx *sql.Tx, vname, cve string, finder, initiator int, summary, test, mitigation string) error {
	return execUpdates(tx, ssInsertVuln, vname, cve, finder, initiator, summary, test, mitigation)
}

// IsVulnOpen returns true if the Vulnerability associated with the passed ID is still open,
// false otherwise.
func IsVulnOpen(vid int64) (bool, error) {
	var vd VulnDates
	err := queries[ssGetVulnDates].QueryRow(vid).Scan(&vd.Published, &vd.Initiated, &vd.Mitigated)
	if err != nil {
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
			err := InsertRef(tx, vuln.ID, r)
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
			err := InsertTicket(tx, vuln.ID, t)
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

// UpdateAffected will update the system ID associated with the (vid, oldSid) row to newSid.
func UpdateAffected(tx *sql.Tx, vid int64, oldSid, newSid int) Err {
	return execUpdates(tx, ssUpdateAffected, newSid, vid, oldSid)
}

// UpdateCve will update the CVE for the given vulnerability ID.
func UpdateCve(tx *sql.Tx, vid int64, cve string) Err {
	return execUpdates(tx, ssUpdateCve, cve, vid)
}

// UpdateCvss will update the CVSS score for the given vulnerability ID.
func UpdateCvss(tx *sql.Tx, vid int64, cvss float32) Err {
	return execUpdates(tx, ssUpdateCvss, cvss, vid)
}

// UpdateCvssLink will update the link to the CVSS score for the given vulnerability ID.
func UpdateCvssLink(tx *sql.Tx, vid int64, cvssLink string) Err {
	return execUpdates(tx, ssUpdateCvssLink, cvssLink, vid)
}

// UpdateCorpScore will update the corporate score for the given vulnerability ID.
func UpdateCorpScore(tx *sql.Tx, vid int64, cscore float32) Err {
	return execUpdates(tx, ssUpdateCorpScore, cscore, vid)
}

// UpdateExploit will update the exploit and the exploitable column for the given vulnerability ID.
// To set the exploitable column to false and have a NULL value for the exploita column, pass in
// an empty string to exploit.
func UpdateExploit(tx *sql.Tx, vid int64, exploit string) Err {
	s := toNullString(exploit)
	return execUpdates(tx, ssUpdateExploit, s.Valid, s, vid)
}

// UpdateInitDate will update the date that the vulnerability assessment was initiated for the given vulnerability ID.
func UpdateInitDate(tx *sql.Tx, vid int64, initDate string) Err {
	return execUpdates(tx, ssUpdateInitDate, initDate, vid)
}

// UpdateMitDate will update the date that the vulnerability assessment was mitigated for the given vulnerability ID.
// To set the mitigation date to NULL, pass in an empty string for mitDate.
func UpdateMitDate(tx *sql.Tx, vid int64, mitDate string) Err {
	s := toNullString(mitDate)
	return execUpdates(tx, ssUpdateMitDate, s, vid)
}

// UpdatePubDate will update the date that the vulnerability was published for the given vulnerability ID.
// To set the published date to NULL, pass in an empty string for pubDate.
func UpdatePubDate(tx *sql.Tx, vid int64, pubDate string) Err {
	s := toNullString(pubDate)
	return execUpdates(tx, ssUpdatePubDate, s, vid)
}

// UpdateRefers will update the url associated with the (vid, oldUrl) row to newUrl.
func UpdateRefers(tx *sql.Tx, vid int64, oldUrl, newUrl string) Err {
	return execUpdates(tx, ssUpdateRefers, newUrl, vid, oldUrl)
}

// UpdateTicket will update the ticket associated with the (vid, oldTicket) row to newTicket.
func UpdateTicket(tx *sql.Tx, vid int64, oldTicket, newTicket string) Err {
	return execUpdates(tx, ssUpdateTicket, newTicket, vid, oldTicket)
}

// execUpdates executes the query referenced by ss in the queries map and returns any errors.
func execUpdates(tx *sql.Tx, ss sqlStatement, args ...interface{}) Err {
	var err Err
	res, e := tx.Stmt(queries[ss]).Exec(args...)
	if e != nil {
		return newErrFromErr(e, execNames[ss])
	}
	if rows, _ := res.RowsAffected(); rows < 1 {
		err = newErr(noRowsUpdated, execNames[ss])
	}
	return err
}
