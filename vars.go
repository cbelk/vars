// Package vars implements the logic of the Vulnerability Assessment Reference System. It will be utilized by the VARS interfaces (varsctl, varsapi, etc).
package vars

import (
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "os"

    _ "github.com/lib/pq"
)

// Conf will hold the VARS configuration.
var Conf VarsConfig

// SQL queries to be used in program execution.
const (
    ActiveSystems   string = "SELECT sysname, location, description FROM systems WHERE state='active';"
    DecomSystem     string = "UPDATE systems SET state='decommissioned' WHERE sysname=$1;"
    InsertSystem    string = "INSERT INTO systems (sysname, location, description, state) VALUES ($1, $2, $3, $4);"
)

// System is the structure that holds information about systems in the environment.
type System struct {
    Name        string
    Location    string
    Description string
}

// VarsConfig is the structure that holds the configuration options for VARS.
type VarsConfig struct {
    Host string
    Port string
    User string
    Pass string
    Name string
}

// ActiveSystems returns a pointer to a slice of System types representing the systems that are currently active.
func GetActiveSystems(db *sql.DB) (*[]System, error) {
    systems := []System{}
    rows, err := db.Query(ActiveSystems)
    if err != nil {
        return &systems, err
    }
    defer rows.Close()
    for rows.Next() {
        var sys System
        if err := rows.Scan(&sys.Name, &sys.Location, &sys.Description); err != nil {
            return &systems, err
        }
        systems = append(systems, sys)
    }
    if err := rows.Err(); err != nil {
        return &systems, err
    }
    return &systems, nil
}

// AddSystem inserts a new systems into the VARS database.
func AddSystem(db *sql.DB, sys *System) error {
    res, err := db.Exec(InsertSystem, sys.Name, sys.Location, sys.Description, "active")
    if rows, _ := res.RowsAffected(); rows < 1 {
        return errors.New("vars: AddSystem: No rows were inserted")
    }
    return err
}

// ConnectDB establishes a connection to the Postgresql database and returns a pointer to the database handler, as well as any errors encountered.
func ConnectDB(conf *VarsConfig) (*sql.DB, error) {
    dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Port, conf.User, conf.Pass, conf.Name)
    db, err := sql.Open("postgres", dbinfo)
    return db, err
}

// DecommissionSystem updates the system table to reflect a decommissioned system.
func DecommissionSystem(db *sql.DB, name string) error {
    res, err := db.Exec(DecomSystem, name)
    if rows, _ := res.RowsAffected(); rows < 1 {
//    if res == nil {
        return errors.New("vars: DecommissionSystem: No rows were updated")
    }
    return err
}

// ReadConfig reads the configurations (specified in JSON format) into the Conf variable (type VarsConfig).
func ReadConfig(config string) (err error) {
    file, err := os.Open(config)
    if err != nil {
        return
    }
    err = json.NewDecoder(file).Decode(&Conf)
    return
}
