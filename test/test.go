package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/lib/pq"
)

var (
	FORMAT  = "2006-01-02"
	systems = []vars.System{
		{Name: "mtx101", Type: "server", OpSys: "ubuntu 1604", Location: "corporate", Description: "Mail relay server"},
		{Name: "mtx102", Type: "router", OpSys: "NA", Location: "hosted", Description: "Some other server"},
		{Name: "mtx103", Type: "server", OpSys: "windows 2012", Location: "hosted", Description: "Some other server again"},
	}
	emps = []vars.Employee{
		{FirstName: "Bob", LastName: "Barker", Email: "bob.barker@test.it", UserName: "user3", Level: 3},
		{FirstName: "Alan", LastName: "Turing", Email: "alan.turing@test.it", UserName: "user0", Level: 0},
		{FirstName: "Aretha", LastName: "Franklin", Email: "aretha.franklin@test.it", UserName: "user2", Level: 2},
		{FirstName: "Pharoahe", LastName: "Monch", Email: "pahroahe.monch@test.it", UserName: "user1", Level: 1},
	}
	vulns = []vars.Vulnerability{
		{Name: "DirtyCOW", Cves: []string{"CVE-2016-5195"}, Cvss: 7.8, CorpScore: 8, CvssLink: vars.VarsNullString{sql.NullString{String: "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-5195&vector=AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Valid: true}}, Finder: 1, Initiator: 3, Summary: "This crap is bad!!!", Test: "Look for a cow in the kernel", Mitigation: "Kill it with fire", Dates: vars.VulnDates{Published: vars.VarsNullTime{pq.NullTime{Time: time.Date(2016, time.November, 10, 1, 2, 3, 4, time.UTC), Valid: true}}}, Tickets: []string{"ticket101", "tciket102"}, References: []string{"https://dirtycow.ninja/", "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"}, Exploit: vars.VarsNullString{sql.NullString{String: "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs", Valid: true}}, Exploitable: vars.VarsNullBool{sql.NullBool{Bool: true, Valid: true}}},
		{Name: "Cortana", Cvss: 9.5, CorpScore: 9.0, Finder: 4, Initiator: 4, Summary: "This junk be spying on ya", Test: "Is Windows installed? Yes? Then you have it :(", Mitigation: "Uninstall windows", Tickets: []string{"ticket911"}, References: []string{"https://img.memesuper.com/164df9ae93ae7920d943f86163fa57d1_microsoft-freak-attack-time-meleney-meme_500-375.jpeg"}},
	}
)

func main() {
	config := flag.String("config", "/etc/vars/vars.conf", "The path to the configuration file")
	flag.Parse()

	// Test reading in config and connecting to DB
	err := varsapi.ReadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Config is:")
	fmt.Println(varsapi.GetConfig(), "\n\n")
	db, err := varsapi.ConnectDB()
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

	// Test updating affected systems
	testUpdateAffected(db, &vulns[0], &systems[0])

	// Test adding notes
	testAddNotes(db)

	// Test getting notes
	testGetNotes()

	// Test updating note
	testUpdateNote(db)

	// Test getting notes again
	testGetNotes()

	// Test closing a VA
	testCloseVulnerability(db, vulns[0].ID)

	// Test getting open/closed VAs
	testGetOpenVAs()
	testGetClosedVAs()

	// Test marshaling/unmarshaling the VARS nullable types
	testNullableJSON()

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

func testAddNotes(db *sql.DB) {
	// Add note to DirtyCOW
	fmt.Printf("Adding note to %v ...\n", vulns[0].Name)
	vid, err := vars.GetVulnID(vulns[0].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	emp, err := varsapi.GetEmployeeByUsername(emps[3].UserName)
	if err != nil {
		log.Fatal(err)
	}
	note := "They just discovered a vulnerability in the patch!!"
	err = varsapi.AddNote(db, vid, emp.ID, note)
	if err != nil {
		log.Fatal(err)
	}

	// Add note to Cortana
	fmt.Printf("Adding note to %v ...\n", vulns[1].Name)
	vid, err = vars.GetVulnID(vulns[1].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	emp, err = varsapi.GetEmployeeByUsername(emps[0].UserName)
	if err != nil {
		log.Fatal(err)
	}
	note = "Maybe we should just get rid of Windows?"
	err = varsapi.AddNote(db, vid, emp.ID, note)
	if err != nil {
		log.Fatal(err)
	}

	// Add another note to Cortana
	fmt.Printf("Adding note to %v ...\n", vulns[1].Name)
	emp, err = varsapi.GetEmployeeByUsername(emps[2].UserName)
	if err != nil {
		log.Fatal(err)
	}
	note = "I agree ^"
	err = varsapi.AddNote(db, vid, emp.ID, note)
	if err != nil {
		log.Fatal(err)
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
	err = varsapi.CloseVulnerability(db, vid)
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
	emp, err := varsapi.GetEmployeeByID(eid)
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

func testGetClosedVAs() {
	fmt.Println("Retrieving closed VAs ...")
	vulns, err := varsapi.GetClosedVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	fmt.Println("Closed vulnerabilities are:")
	for _, vuln := range vulns {
		fmt.Println(*vuln)
		fmt.Printf("\nSystems affected by %v are:\n", vuln.Name)
		for _, a := range vuln.AffSystems {
			fmt.Println(*a)
		}
	}
}

func testGetNotes() {
	fmt.Printf("Retrieving notes for %v:\n", vulns[1].Name)
	vid, err := vars.GetVulnID(vulns[1].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	notes, err := varsapi.GetNotes(vid)
	if err != nil {
		log.Fatal(err)
	}
	for _, n := range notes {
		fmt.Println(n)
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
		fmt.Printf("\nSystems affected by %v are:\n", vuln.Name)
		for _, a := range vuln.AffSystems {
			fmt.Println(*a)
		}
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
		fmt.Printf("\nSystems affected by %v are:\n", v.Name)
		for _, a := range v.AffSystems {
			fmt.Println(*a)
		}
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

func testNullableJSON() {
	fmt.Println("Testing [un]marshaling vulnerabilities ...")
	vulns, err := varsapi.GetVulnerabilities()
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	for _, v := range vulns {
		fmt.Printf("\nMarshaling vulnerability %v ...\n", v.Name)
		mv, err := json.Marshal(v)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\nMarshaled data is:\n%v\n", string(mv))
		fmt.Printf("\nUnmarshaling vulnerability %v ...\n", v.Name)
		var n vars.Vulnerability
		err = json.Unmarshal(mv, &n)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\nUnmarshaled vulnerability is:\n%v\nOriginal is\n%v\n", n, *v)
	}
}

func testUpdateAffected(db *sql.DB, vuln *vars.Vulnerability, sys *vars.System) {
	fmt.Printf("\nUpdating the mitigated status to true for vulnerability %v affecting system %v ...\n", vuln.Name, sys.Name)
	sid, err := vars.GetSystemID(sys.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	vid, err := vars.GetVulnID(vuln.Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}

	err = varsapi.UpdateAffected(db, vid, sid, true)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
}

func testUpdateEmployee(db *sql.DB, item int64) {
	nEmp := emps[item]
	fmt.Printf("Updating employee %v %v ...\n", nEmp.FirstName, nEmp.LastName)
	id, err := vars.GetEmpID(nEmp.UserName)
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

func testUpdateNote(db *sql.DB) {
	fmt.Printf("Updating last note for %v:\n", vulns[1].Name)
	vid, err := vars.GetVulnID(vulns[1].Name)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	notes, err := varsapi.GetNotes(vid)
	if err != nil {
		log.Fatal(err)
	}
	nid := notes[len(notes)-1].ID
	note := fmt.Sprintf("I agree with %v %v", emps[0].FirstName, emps[0].LastName)
	err = varsapi.UpdateNote(db, nid, note)
	if err != nil {
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
	vuln.Dates.Published = varsapi.GetVarsNullTime(time.Date(1970, time.January, 1, 5, 4, 3, 2, time.UTC))
	vuln.Tickets = append(vuln.Tickets, "ticket411")
	vuln.Tickets[0] = "ticket917"
	vuln.References = []string{"some new reference"}
	vuln.Cves = append(vuln.Cves, "CVE-2088-1234")
	err = varsapi.UpdateVulnerability(db, vuln)
	if !vars.IsNilErr(err) {
		log.Fatal(err)
	}
	testGetVulnerability(vuln.Name)
}
