// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "os"

    _ "github.com/lib/pq" // Postgresql driver
)

// Conf will hold the VARS configuration.
var Conf Config

// SQL queries to be used in program execution.
const (
    ActiveSystems   string = "SELECT sysid, sysname, systype, opsys, location, description FROM systems WHERE state='active';"
    DecomSystem     string = "UPDATE systems SET state='decommissioned' WHERE sysname=$1;"
    InsertSystem    string = "INSERT INTO systems (sysname, systype, opsys, location, description, state) VALUES ($1, $2, $3, $4, $5, $6);"
    InsertVuln      string = "INSERT INTO vuln (vulnname, cve, finder, initiator, summary, test, mitigation) VALUES ($1, $2, $3, $4, $5, $6, $7);"
    UpdateCvss      string = "UPDATE impact SET cvss=$1 WHERE vulnid=$2;"
    UpdateCvssLink  string = "UPDATE impact SET cvsslink=$1 WHERE vulnid=$2;"
    UpdateCorpScore string = "UPDATE impact SET corpscore=$1 WHERE vulnid=$2;"
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
    ID          int
    FirstName   string
    LastName    string
    Email       string
}

// System holds information about systems in the environment.
type System struct {
    ID          int
    Name        string
    Type        string  // Server, router, switch, etc
    OpSys       string
    Location    string  // Corporate, hosted, etc
    Description string
    State       string  // Active or decommissioned
}

// Vulnerability holds information about a discovered vulnerability and the vulnerability assessment.
type Vulnerability struct {
    ID          int
    Name        string
    Cve         string
    Cvss        float32     // CVSS score
    CorpScore   float32     // Calculated corporate score
    CvssLink    string      // Link to CVSS scoresheet
    Finder      int         // Employee that found the vulnerability
    Initiator   int         // Employee that started the vulnerability assessment
    Summary     string
    Test        string      // Test to see if system has this vulnerability
    Mitigation  string
    Published   string      // Date the vulnerability was made public
    Initiated   string      // Date the vulnerability assessment was started
    Mitigated   string      // Date the vulnerability was mitigated on all systems
    Tickets     []string    // Tickets relating to the vulnerability
    References  []string    // Reference URLs
    Exploit     string      // Exploit for the vulnerability
    Exploitable bool        // Are there currently exploits for the vulnerability
}

// AddSystem inserts a new systems into the VARS database.
func AddSystem(db *sql.DB, sys *System) error {
    res, err := db.Exec(InsertSystem, sys.Name, sys.Type, sys.OpSys, sys.Location, sys.Description, "active")
    if rows, _ := res.RowsAffected(); rows < 1 {
        return errors.New("vars: AddSystem: No rows were inserted")
    }
    return err
}

// AddVulnerability starts a new vulnerability assessment by inserting a new vulnerability.
func AddVulnerability(db *sql.DB, vuln *Vulnerability) error {
    res, err := db.Exec(InsertVuln, vuln.Name, vuln.Cve, vuln.Finder, vuln.Initiator, vuln.Summary, vuln.Test, vuln.Mitigation)
    if rows, _ := res.RowsAffected(); rows < 1 {
        return errors.New("vars: AddVulnerability: No rows were inserted")
    }
    if err != nil {
        return err
    }
    if err := SetCvss(db, vuln); err != nil {
        return err
    }
    return nil
}

// ConnectDB establishes a connection to the Postgresql database and returns a pointer to the database handler, as well as any errors encountered.
func ConnectDB(conf *Config) (*sql.DB, error) {
    dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Port, conf.User, conf.Pass, conf.Name)
    db, err := sql.Open("postgres", dbinfo)
    return db, err
}

// DecommissionSystem updates the system table to reflect a decommissioned system.
func DecommissionSystem(db *sql.DB, name string) error {
    res, err := db.Exec(DecomSystem, name)
    if rows, _ := res.RowsAffected(); rows < 1 {
        return errors.New("vars: DecommissionSystem: No rows were updated")
    }
    return err
}

// GetActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems(db *sql.DB) (*[]System, error) {
    systems := []System{}
    rows, err := db.Query(ActiveSystems)
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
func SetCvss(db *sql.DB, vuln *Vulnerability) error {
    if vuln.Cvss != 0 {
        res, err := db.Exec(UpdateCvss, vuln.Cvss, vuln.ID)
        if rows, _ := res.RowsAffected(); rows < 1 {
            return errors.New("vars: SetCvss: Cvss: No rows were updated")
        }
        if err != nil {
            return err
        }
    }
    if vuln.CvssLink != "" {
        res, err := db.Exec(UpdateCvssLink, vuln.CvssLink, vuln.ID)
        if rows, _ := res.RowsAffected(); rows < 1 {
            return errors.New("vars: SetCvss: CvssLink: No rows were updated")
        }
        if err != nil {
            return err
        }
    }
    if vuln.CorpScore != 0 {
        res, err := db.Exec(UpdateCorpScore, vuln.CorpScore, vuln.ID)
        if rows, _ := res.RowsAffected(); rows < 1 {
            return errors.New("vars: SetCvss: CorpScore: No rows were updated")
        }
        if err != nil {
            return err
        }
    }
    return nil
}
