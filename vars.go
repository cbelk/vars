// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq" // Postgresql driver
)

// Conf will hold the VARS configuration.
var Conf Config

type sqlStatement int

const (
	ssActiveSystems sqlStatement = iota
	ssDecomSystem
	ssInsertExploit
	ssInsertRefers
	ssInsertSystem
	ssInsertTicket
	ssInsertVuln
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
		ssInsertExploit:   "INSERT INTO exploits (vulnid, exploitable, exploit) VALUES ($1, $2, $3);",
		ssInsertRefers:    "INSERT INTO ref (vulnid, url) VALUES ($1, $2);",
		ssInsertSystem:    "INSERT INTO systems (sysname, systype, opsys, location, description, state) VALUES ($1, $2, $3, $4, $5, $6);",
		ssInsertTicket:    "INSERT INTO tickets (vulnid, ticket) VALUES ($1, $2);",
		ssInsertVuln:      "INSERT INTO vuln (vulnname, cve, finder, initiator, summary, test, mitigation) VALUES ($1, $2, $3, $4, $5, $6, $7);",
		ssUpdateCvss:      "UPDATE impact SET cvss=$1 WHERE vulnid=$2;",
		ssUpdateCvssLink:  "UPDATE impact SET cvsslink=$1 WHERE vulnid=$2;",
		ssUpdateCorpScore: "UPDATE impact SET corpscore=$1 WHERE vulnid=$2;",
		ssUpdateInitDate:  "UPDATE dates SET initiated=$1 WHERE vulnid=$2;",
		ssUpdateMitDate:   "UPDATE dates SET mitigated=$1 WHERE vulnid=$2;",
		ssUpdatePubDate:   "UPDATE dates SET published=$1 WHERE vulnid=$2;",
	}
)

// Config holds the configuration options for VARS.
type Config struct {
	Host string
	Port string
	User string
	Pass string
	Name string
}

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

// Vulnerability holds information about a discovered vulnerability and the vulnerability assessment.
type Vulnerability struct {
	ID          int
	Name        string
	Cve         string
	Cvss        float32 // CVSS score
	CorpScore   float32 // Calculated corporate score
	CvssLink    string  // Link to CVSS scoresheet
	Finder      int     // Employee that found the vulnerability
	Initiator   int     // Employee that started the vulnerability assessment
	Summary     string
	Test        string // Test to see if system has this vulnerability
	Mitigation  string
	Published   string   // Date the vulnerability was made public
	Initiated   string   // Date the vulnerability assessment was started
	Mitigated   string   // Date the vulnerability was mitigated on all systems
	Tickets     []string // Tickets relating to the vulnerability
	References  []string // Reference URLs
	Exploit     string   // Exploit for the vulnerability
	Exploitable bool     // Are there currently exploits for the vulnerability
}

// AddSystem inserts a new systems into the VARS database.
func AddSystem(db *sql.DB, sys *System) error {
	res, err := queries[ssInsertSystem].Exec(sys.Name, sys.Type, sys.OpSys, sys.Location, sys.Description, "active")
	if rows, _ := res.RowsAffected(); rows < 1 {
		return errors.New("vars: AddSystem: No rows were inserted")
	}
	return err
}

// AddVulnerability starts a new vulnerability assessment by inserting a new vulnerability.
func AddVulnerability(db *sql.DB, vuln *Vulnerability) error {
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
		err = errors.New("vars: AddVulnerability: No rows were inserted")
	}
	if e := SetCvss(tx, vuln); e != nil {
		if !strings.Contains(e.Error(), "No rows were") {
			return e
		}
		err = e
	}
	if e := SetDates(tx, vuln); e != nil {
		if !strings.Contains(e.Error(), "No rows were") {
			return e
		}
		err = e
	}
	if e := SetTickets(tx, vuln); e != nil {
		if !strings.Contains(e.Error(), "No rows were") {
			return e
		}
		err = e
	}
	if e := SetReferences(tx, vuln); e != nil {
		if !strings.Contains(e.Error(), "No rows were") {
			return e
		}
		err = e
	}
	rollback = false
	return tx.Commit()
}

// ConnectDB establishes a connection to the Postgresql database and returns a pointer to the database handler, as well as any errors encountered.
func ConnectDB(conf *Config) (*sql.DB, error) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Port, conf.User, conf.Pass, conf.Name)
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		return nil, err
	}
	if err = prepareStatements(db); err != nil {
		return nil, err
	}
	return db, nil
}

//CloseDB is a way to close connections to the database safely
func CloseDB(db *sql.DB) {
	closeStatements()
	db.Close()
}

func closeStatements() {
	if queries == nil {
		return
	}
	for _, stmt := range queries {
		stmt.Close()
	}
}

func prepareStatements(db *sql.DB) error {
	if queries == nil {
		queries = make(map[sqlStatement]*sql.Stmt)
	}
	for name, sql := range queryStrings {
		stmt, err := db.Prepare(sql)
		if err != nil {
			return err
		}
		queries[name] = stmt
	}
	return nil
}

// DecommissionSystem updates the system table to reflect a decommissioned system.
func DecommissionSystem(db *sql.DB, name string) error {
	res, err := queries[ssDecomSystem].Exec(name)
	if rows, _ := res.RowsAffected(); rows < 1 {
		return errors.New("vars: DecommissionSystem: No rows were updated")
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

// ReadConfig reads the configurations (specified in JSON format) into the Conf variable (type Config).
func ReadConfig(config string) (err error) {
	file, err := os.Open(config)
	if err != nil {
		return
	}
	err = json.NewDecoder(file).Decode(&Conf)
	return
}

// SetCvss updates the CVSS score and links and the Corporate Risk Score for a vulnerability.
// It will not do a partial update as in if something fails, the transaction is rolled back.
func SetCvss(tx *sql.Tx, vuln *Vulnerability) error {
	if vuln.Cvss != 0 {
		res, err := tx.Stmt(queries[ssUpdateCvss]).Exec(vuln.Cvss, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetCvss: Cvss: No rows were updated")
		}
	}
	if vuln.CvssLink != "" {
		res, err := tx.Stmt(queries[ssUpdateCvssLink]).Exec(vuln.CvssLink, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetCvss: CvssLink: No rows were updated")
		}
	}
	if vuln.CorpScore != 0 {
		res, err := tx.Stmt(queries[ssUpdateCorpScore]).Exec(vuln.CorpScore, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetCvss: CorpScore: No rows were updated")
		}
	}
	return nil
}

// SetDates updates the dates published, initiated, and mitigated.
func SetDates(tx *sql.Tx, vuln *Vulnerability) error {
	if vuln.Published != "" {
		res, err := tx.Stmt(queries[ssUpdatePubDate]).Exec(vuln.Published, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetDates: Published: No rows were updated")
		}
	}
	if vuln.Initiated != "" {
		res, err := tx.Stmt(queries[ssUpdateInitDate]).Exec(vuln.Published, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetDates: Initiated: No rows were updated")
		}
	}
	if vuln.Mitigated != "" {
		res, err := tx.Stmt(queries[ssUpdateMitDate]).Exec(vuln.Published, vuln.ID)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			return errors.New("vars: SetDates: Mitigated: No rows were updated")
		}
	}
	return nil
}

// SetExploits inserts an entry into the exploits table if the exploit string isn't zero valued.
func SetExploits(tx *sql.Tx, vuln *Vulnerability) error {
	var err error
	if vuln.Exploit != "" {
		res, err := tx.Stmt(queries[ssInsertExploit]).Exec(vuln.ID, true, vuln.Exploit)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows < 1 {
			err = errors.New("vars: SetExploits: No rows were inserted")
		}
	}
	return err
}

// SetTickets inserts entries into the tickets table for all ticket ID's in the slice.
func SetTickets(tx *sql.Tx, vuln *Vulnerability) error {
	var err error
	if len(vuln.Tickets) > 0 {
		for _, t := range vuln.Tickets {
			res, err := tx.Stmt(queries[ssInsertTicket]).Exec(vuln.ID, t)
			if err != nil {
				return err
			}
			if rows, _ := res.RowsAffected(); rows < 1 {
				err = errors.New("vars: SetTickets: No rows were inserted")
			}
		}
	}
	return err
}

// SetReferences inserts entries into the ref table for all URLs in the slice.
func SetReferences(tx *sql.Tx, vuln *Vulnerability) error {
	var err error
	if len(vuln.References) > 0 {
		for _, r := range vuln.References {
			res, err := tx.Stmt(queries[ssInsertRefers]).Exec(vuln.ID, r)
			if err != nil {
				return err
			}
			if rows, _ := res.RowsAffected(); rows < 1 {
				err = errors.New("vars: SetReferences: No rows were inserted")
			}
		}
	}
	return err
}
