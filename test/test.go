package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
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
	vulns = []vars.Vulnerability{
		{Name: "DirtyCOW", Cve: vars.VarsNullString{sql.NullString{String: "CVE-2016-5195", Valid: true}}, Cvss: 7.8, CorpScore: 8, CvssLink: vars.VarsNullString{sql.NullString{String: "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-5195&vector=AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Valid: true}}, Finder: 1, Initiator: 3, Summary: "This crap is bad!!!", Test: "Look for a cow in the kernel", Mitigation: "Kill it with fire", Dates: vars.VulnDates{Published: vars.VarsNullString{sql.NullString{String: "11/10/2016", Valid: true}}, Initiated: "11/11/2016"}, Tickets: []string{"ticket101", "tciket102"}, References: []string{"https://dirtycow.ninja/", "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"}, Exploit: vars.VarsNullString{sql.NullString{String: "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs", Valid: true}}, Exploitable: vars.VarsNullBool{sql.NullBool{Bool: true, Valid: true}}},
		{Name: "Cortana", Cvss: 9.5, CorpScore: 9.0, Finder: 4, Initiator: 4, Summary: "This junk be spying on ya", Test: "Is Windows installed? Yes? Then you have it :(", Mitigation: "Uninstall windows", Dates: vars.VulnDates{Initiated: "1/1/1970"}, Tickets: []string{"ticket911"}, References: []string{"https://img.memesuper.com/164df9ae93ae7920d943f86163fa57d1_microsoft-freak-attack-time-meleney-meme_500-375.jpeg"}},
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
	fmt.Println(vars.Conf, "\n\n")
	db, err := vars.ConnectDB(&vars.Conf)
	if err != nil {
		log.Fatal(err)
	}

	// Test adding all systems
	fmt.Println("Adding systems ...\n\n")
	err = testAddSystems(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test getting all active systems
	fmt.Println("Active systems are:")
	err = testGetActiveSystems()
	if err != nil {
		log.Fatal(err)
	}

	// Test adding all employees
	fmt.Println("Adding employees ...\n\n")
	err = testAddEmps(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test decomissioning a system
	s := 2
	fmt.Println("Decomissioning system ", systems[s].Name, "\n")
	err = testDecomSystem(db, systems[s])
	if err != nil {
		log.Fatal(err)
	}

	// Test getting all active systems again
	fmt.Println("Active systems are:")
	err = testGetActiveSystems()
	if err != nil {
		log.Fatal(err)
	}

	// Test adding vulnerabilites
	fmt.Println("Adding vulnerabilities ...\n\n")
	err = testAddVulnerabilities(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test getting vulnerabilities
	v := 1
	fmt.Println("Vulnerability is:")
	err = testGetVulnerability(vulns[v].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	err = testGetVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	fmt.Println("Done!")
}

func testGetVulnerability(vname string) error {
	fmt.Printf("vname is %v\n\n", vname)
	vid, err := vars.GetVulnID(vname)
	if err != nil {
		return err
	}
	vuln, err := vars.GetVulnerability(vid)
	if !vars.IsNilErr(err) {
		return err
	}
	fmt.Println(vuln)
	return nil
}

func testGetVulnerabilities() error {
	vulns, err := vars.GetVulnerabilities()
	if !vars.IsNilErr(err) {
		return err
	}
	for _, vuln := range vulns {

		// Get dates
		vd, err := vars.GetVulnDates(vuln.ID)
		if !vars.IsNilErr(err) {
			return err
		}
		vuln.Dates = *vd

		// Get tickets
		ticks, err := vars.GetTickets(vuln.ID)
		if !vars.IsNilErr(err) {
			return err
		}
		vuln.Tickets = *ticks

		// Get references
		refs, err := vars.GetReferences(vuln.ID)
		if !vars.IsNilErr(err) {
			return err
		}
		vuln.References = *refs

		// Get exploit
		exploit, exploitable, err := vars.GetExploit(vuln.ID)
		if !vars.IsNilErr(err) {
			return err
		}
		vuln.Exploit = exploit
		vuln.Exploitable = exploitable

		fmt.Printf("Vulnerability:\n%v\n", *vuln)
	}
	return nil
}

func testAddSystems(db *sql.DB) error {
	for _, v := range systems {
		err := varsapi.AddSystem(db, &v)
		if err != nil {
			return err
		}
	}
	return nil
}

func testAddEmps(db *sql.DB) error {
	for _, v := range emps {
		err := vars.AddEmployee(db, &v)
		if err != nil {
			return err
		}
	}
	return nil
}

func testDecomSystem(db *sql.DB, stms ...vars.System) error {
	for _, v := range stms {
		err := varsapi.DecommissionSystem(db, &v)
		if err != nil {
			return err
		}
	}
	return nil
}

func testGetActiveSystems() error {
	syss, err := vars.GetActiveSystems()
	if err != nil {
		return err
	}
	for _, sys := range *syss {
		fmt.Println(sys, "\n")
	}
	return nil
}

func testAddVulnerabilities(db *sql.DB) error {
	for _, v := range vulns {
		err := varsapi.AddVulnerability(db, &v)
		if !vars.IsNilErr(err) {
			return err
		}
	}
	return nil
}
