package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
)

var (
	FORMAT  = "2006-01-02"
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
	testAddSystems(db)

	// Test getting all systems
	testGetSystems()

	// Test adding all employees
	testAddEmps(db)

	// Test getting all employees
	testGetEmployees()

	// Test updating employee
	testUpdateEmployee(db, 0)

	// Test getting the updated employee
	testGetEmployee(1)

	// Test updating a system
	testUpdateSystem(db)

	// Test decomissioning a system
	testDecomSystem(db, systems[1])

	// Test getting all active systems again
	testGetActiveSystems()

	// Test adding vulnerabilites
	testAddVulnerabilities(db)

	// Test getting vulnerabilities
	testGetVulnerability(vulns[0].Name)
	testGetVulnerability(vulns[1].Name)

	// Test updating vuln
	testUpdateVulnerability(db)

	// Test getting all vulnerabilities
	testGetVulnerabilities()

	// Test getting systems
	testGetSystem(systems[0].Name)
	testGetSystem(systems[1].Name)
	testGetSystem(systems[2].Name)

	// Test adding affected systems
	testAddAffected(db, &vulns[0], &systems[0])
	testAddAffected(db, &vulns[1], &systems[2])

	// Test closing a VA
	testCloseVulnerability(db, vulns[0].ID)

	// Test getting open VAs
	testGetOpenVAs()

	fmt.Println("\n\nDone!")
}

func testAddAffected(db *sql.DB, vuln *vars.Vulnerability, sys *vars.System) {
	fmt.Printf("\nAdding system %v affected by vulnerability %v ...\n", sys.Name, vuln.Name)
	sid, err := vars.GetSystemID(sys.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	sys.ID = sid
	vid, err := vars.GetVulnID(vuln.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	vuln.ID = vid
	err = varsapi.AddAffected(db, vuln, sys)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
}

func testAddEmps(db *sql.DB) {
	fmt.Println("\nAdding employees ...\n\n")
	for _, v := range emps {
		fmt.Printf("Adding employee %v %v ...\n", v.FirstName, v.LastName)
		err := varsapi.AddEmployee(db, &v)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}
}

func testAddSystems(db *sql.DB) {
	fmt.Println("Adding systems ...\n")
	for _, v := range systems {
		fmt.Printf("Adding system %v ...\n", v.Name)
		err := varsapi.AddSystem(db, &v)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}
}

func testAddVulnerabilities(db *sql.DB) {
	fmt.Println("Adding vulnerabilities ...\n")
	for _, v := range vulns {
		fmt.Printf("Adding vulnerability %v ...\n", v.Name)
		err := varsapi.AddVulnerability(db, &v)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}
}

func testCloseVulnerability(db *sql.DB, vid int64) {
	vuln, err := varsapi.GetVulnerability(vid)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Printf("Closing vulnerability: %v ...\n", vuln.Name)
	now := varsapi.GetVarsNullString(time.Now().Format(FORMAT))
	err = varsapi.CloseVulnerability(db, vid, now)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
}

func testDecomSystem(db *sql.DB, stms ...vars.System) {
	for _, v := range stms {
		fmt.Printf("Decomissioning system %v ...\n", v.Name)
		sid, err := vars.GetSystemID(v.Name)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
		v.ID = sid
		err = varsapi.DecommissionSystem(db, &v)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}
}

func testGetActiveSystems() {
	fmt.Println("Active systems are:")
	syss, err := vars.GetActiveSystems()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	for _, sys := range syss {
		fmt.Printf("%v\n", *sys)
	}
}

func testGetEmployee(eid int64) {
	fmt.Printf("Retrieving employee with ID %v ...\n", eid)
	emp, err := varsapi.GetEmployee(eid)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println(emp)
}

func testGetEmployees() {
	fmt.Println("Retrieving employees ...")
	emps, err := varsapi.GetEmployees()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	for _, emp := range emps {
		fmt.Printf("Struct for %v %v:\n%v\n", emp.FirstName, emp.LastName, emp)
	}
}

func testGetOpenVAs() {
	fmt.Println("Retrieving open VAs ...")
	vulns, err := varsapi.GetOpenVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("Open vulnerabilities are:")
	for _, vuln := range vulns {
		fmt.Println(*vuln)
	}
}

func testGetSystem(sysname string) {
	fmt.Printf("Retrieving system %v:\n", sysname)
	sys, err := varsapi.GetSystemByName(sysname)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", sys)
}

func testGetSystems() {
	fmt.Println("Retrieving all systems ...")
	syss, err := varsapi.GetSystems()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	for _, s := range syss {
		fmt.Println(*s)
	}
}

func testGetVulnerabilities() {
	fmt.Println("Retrieving all vulnerabilities ...")
	vulns, err := varsapi.GetVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	for _, v := range vulns {
		fmt.Println(*v)
	}
}

func testGetVulnerability(vname string) {
	fmt.Printf("Retrieving vulnerability %v:\n", vname)
	vuln, err := varsapi.GetVulnerabilityByName(vname)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", vuln)
}

func testUpdateEmployee(db *sql.DB, item int64) {
	nEmp := emps[item]
	fmt.Printf("Updating employee %v %v ...\n", nEmp.FirstName, nEmp.LastName)
	id, err := vars.GetEmpID(nEmp.FirstName, nEmp.LastName, nEmp.Email)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	nEmp.ID = id
	nEmp.Email = fmt.Sprintf("%v.%v@newemail.com", nEmp.FirstName, nEmp.LastName)
	err = varsapi.UpdateEmployee(db, &nEmp)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
}

func testUpdateSystem(db *sql.DB) {
	nSys := vars.System{Name: "mtx102", Type: "router", OpSys: "KasperkyOS", Location: "hosted", Description: "Some other server"}
	fmt.Printf("Updating system %v ...\n", nSys.Name)
	id, err := vars.GetSystemID(nSys.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	nSys.ID = id
	err = varsapi.UpdateSystem(db, &nSys)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	testGetSystem(nSys.Name)
}

func testUpdateVulnerability(db *sql.DB) {
	fmt.Printf("Updating vulnerability %v ...\n", vulns[1].Name)
	vuln, err := varsapi.GetVulnerabilityByName(vulns[1].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	vuln.Dates.Published = vars.ToVarsNullString("1/1/1970")
	vuln.Tickets = append(vuln.Tickets, "ticket411")
	vuln.Tickets[0] = "ticket917"
	vuln.References = []string{"some new reference"}
	err = varsapi.UpdateVulnerability(db, vuln)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	testGetVulnerability(vuln.Name)
}
