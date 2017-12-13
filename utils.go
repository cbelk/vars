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

package vars

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/lib/pq" // Postgresql driver
)

// Config holds the configuration options for VARS.
type Config struct {
	Host string
	Port string
	User string
	Pass string
	Name string
}

// Conf will hold the VARS configuration.
var Conf Config

// ReadConfig reads the configurations (specified in JSON format) into the Conf variable (type Config).
func ReadConfig(config string) (err error) {
	file, err := os.Open(config)
	if err != nil {
		return
	}
	err = json.NewDecoder(file).Decode(&Conf)
	return
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

// CloseDB is a way to close connections to the database safely
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
	for name, ss := range queryStrings {
		stmt, err := db.Prepare(ss)
		if err != nil {
			return err
		}
		queries[name] = stmt
	}
	return nil
}

// toNullString invalidates a sql.NullString if empty, validates if not empty.
func toNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// ToVarsNullString creates a VarsNullString from a string.
func ToVarsNullString(s string) VarsNullString {
	return VarsNullString{toNullString(s)}
}
