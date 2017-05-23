package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	"github.com/cbelk/vars"
)

var (
	systems = []vars.System{
		{Name: "mtx101", Type: "server", OpSys: "ubuntu 1604", Location: "corporate", Description: "Mail relay server"},
		{Name: "mtx102", Type: "router", OpSys: "NA", Location: "hosted", Description: "Some other server"},
		{Name: "mtx103", Type: "server", OpSys: "windows 2012", Location: "hosted", Description: "Some other server again"},
	}
	emps = []vars.Employee{
		{FirstName: "Bob", LastName: "Barker", Email: "bob.barker@test.it"},
		{FirstName: "Alan", LastName: "Turing", Email: "alan.turing@test.it"},
		{FirstName: "Aretha", LastName: "Franklin", Email: "aretha.franklin@test.it"},
		{FirstName: "Pharoahe", LastName: "Monch", Email: "pahroahe.monch@test.it"},
	}
)

func main() {
	config := flag.String("config", "/etc/vars/vars.conf", "The path to the configuration file")
	flag.Parse()

	// Test reading in config and connecting to DB
	err := vars.ReadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Config is:")
	fmt.Println(vars.Conf, "\n")
	db, err := vars.ConnectDB(&vars.Conf)
	if err != nil {
		log.Fatal(err)
	}

	// Test adding all systems
	err = testAddSystems(db, 0, 1, 2)
	if err != nil {
		log.Fatal(err)
	}

	// Test getting all active systems
	err = testGetActiveSystems(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test adding all employees
	err = testAddEmps(db, 0, 1, 2, 3)
	if err != nil {
		log.Fatal(err)
	}

	// Test decomissioning a system
	err = testDecomSystem(db, 2)
	if err != nil {
		log.Fatal(err)
	}

	// Test getting all active systems again
	err = testGetActiveSystems(db)
	if err != nil {
		log.Fatal(err)
	}
}

func testAddSystems(db *sql.DB, stms ...int) error {
	for _, v := range stms {
		err := vars.AddSystem(db, &systems[v])
		if err != nil {
			return err
		}
	}
	return nil
}

func testAddEmps(db *sql.DB, eps ...int) error {
	for _, v := range eps {
		err := vars.AddEmployee(db, &emps[v])
		if err != nil {
			return err
		}
	}
	return nil
}

func testDecomSystem(db *sql.DB, stms ...int) error {
	for _, v := range stms {
		err := vars.DecommissionSystem(db, systems[v].Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func testGetActiveSystems(db *sql.DB) error {
	syss, err := vars.GetActiveSystems(db)
	if err != nil {
		return err
	}
	for _, sys := range *syss {
		fmt.Println(sys)
	}
	return nil
}
