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
		{Name: "Cortana", Cvss: 9.5, CorpScore: 9.0, Finder: 4, Initiator: 4, Summary: "This junk be spying on ya", Test: "Is Windows installed? Yes? Then you have it :(", Mitigation: "Uninstall windows", Dates: vars.VulnDates{Initiated: "1/2/1970"}, Tickets: []string{"ticket911"}, References: []string{"https://img.memesuper.com/164df9ae93ae7920d943f86163fa57d1_microsoft-freak-attack-time-meleney-meme_500-375.jpeg"}},
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
	fmt.Println("\n\nActive systems are:")
	err = testGetActiveSystems()
	if err != nil {
		log.Fatal(err)
	}

	// Test adding all employees
	fmt.Println("\n\nAdding employees ...\n\n")
	err = testAddEmps(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test updating a system
	fmt.Println("\n\nUpdating system...\n")
	nSys := vars.System{Name: "mtx102", Type: "router", OpSys: "KasperkyOS", Location: "hosted", Description: "Some other server"}
	id, err := vars.GetSystemID(nSys.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	nSys.ID = id
	err = varsapi.UpdateSystem(db, &nSys)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	ns, err := testGetSystem(nSys.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("\n\nRetrieving system 0")
	fmt.Println(ns)

	// Test decomissioning a system
	s := 1
	fmt.Println("\n\nDecomissioning system ", systems[s].Name, "\n")
	err = testDecomSystem(db, systems[s])
	if err != nil {
		log.Fatal(err)
	}

	// Test getting all active systems again
	fmt.Println("\n\nActive systems are:")
	err = testGetActiveSystems()
	if err != nil {
		log.Fatal(err)
	}

	// Test adding vulnerabilites
	fmt.Println("\n\nAdding vulnerabilities ...\n\n")
	err = testAddVulnerabilities(db)
	if err != nil {
		log.Fatal(err)
	}

	// Test getting vulnerabilities
	v0, err := testGetVulnerability(vulns[0].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("\n\nRetrieving vulnerability 0")
	fmt.Println(v0)

	v1, err := testGetVulnerability(vulns[1].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("\n\nRetrieving vulnerability 1")
	fmt.Println(v1)

	// Test updating vuln
	v1.Dates.Published = vars.ToVarsNullString("1/1/1970")
	v1.References = append(v1.References, "someOther.ref")
	err = varsapi.UpdateVulnerability(db, v1)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	fmt.Println("\n\nRetrieving vulnerabilities\n")
	err = testGetVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	// Test getting systems
	s0, err := testGetSystem(systems[0].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("\n\nRetrieving system 0")
	fmt.Println(s0)

	s2, err := testGetSystem(systems[2].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("\n\nRetrieving system 2")
	fmt.Println(s2)

	// Test adding affected systems
	fmt.Println("\n\nAdding affected systems ...\n\n")
	err = testAddAffected(db, v0, s0)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	err = testAddAffected(db, v1, s2)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	fmt.Println("\n\nDone!")
}

func testAddAffected(db *sql.DB, vuln *vars.Vulnerability, sys *vars.System) error {
	fmt.Printf("\n\nAdding vulnid %v sysid %v\n", vuln.ID, sys.ID)
	return varsapi.AddAffected(db, vuln, sys)
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

func testAddSystems(db *sql.DB) error {
	for _, v := range systems {
		err := varsapi.AddSystem(db, &v)
		if err != nil {
			return err
		}
		fmt.Printf("\n\nAdded system: %v\n\n", v)
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

func testDecomSystem(db *sql.DB, stms ...vars.System) error {
	for _, v := range stms {
		sid, err := vars.GetSystemID(v.Name)
		if err != nil {
			return err
		}
		v.ID = sid
		err = varsapi.DecommissionSystem(db, &v)
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

func testGetSystem(sysname string) (*vars.System, error) {
	fmt.Printf("\n\nsysname is %v\n\n", sysname)
	var s vars.System
	sid, err := vars.GetSystemID(sysname)
	if err != nil {
		return &s, err
	}
	sys, err := vars.GetSystem(sid)
	if err != nil {
		return &s, err
	}
	return sys, nil
}

func testGetVulnerability(vname string) (*vars.Vulnerability, error) {
	fmt.Printf("\n\nvname is %v\n\n", vname)
	var v vars.Vulnerability
	vid, err := vars.GetVulnID(vname)
	if err != nil {
		return &v, err
	}
	vuln, err := vars.GetVulnerability(vid)
	if !vars.IsNilErr(err) {
		return &v, err
	}
	return vuln, nil
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

		fmt.Printf("\n\nVulnerability:\n%v\n", *vuln)
	}
	return nil
}
