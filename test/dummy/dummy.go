package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/cbelk/vars"
	"github.com/cbelk/vars/pkg/varsapi"
	"github.com/lib/pq"
)

var (
	emps = []vars.Employee{
		{FirstName: "Bob", LastName: "Barker", Email: "bob.barker@test.it", UserName: "user3", Level: 3},
		{FirstName: "Alan", LastName: "Turing", Email: "alan.turing@test.it", UserName: "user0", Level: 0},
		{FirstName: "Aretha", LastName: "Franklin", Email: "aretha.franklin@test.it", UserName: "user2", Level: 2},
		{FirstName: "Pharoahe", LastName: "Monch", Email: "pahroahe.monch@test.it", UserName: "user1", Level: 1},
		{FirstName: "Ismael", LastName: "Diaz", Email: "ismael.diaz@test.it", UserName: "ismaeld", Level: 2},
		{FirstName: "Aaron", LastName: "Williams", Email: "aaron.williams@test.it", UserName: "aaronw", Level: 1},
		{FirstName: "Sara", LastName: "Davidson", Email: "sara.davidson@test.it", UserName: "sarad", Level: 1},
		{FirstName: "Florian", LastName: "Guillot", Email: "florian.guillot@test.it", UserName: "floriang", Level: 3},
		{FirstName: "Roope", LastName: "Lampinen", Email: "roope.lampinen@test.it", UserName: "roopel", Level: 2},
		{FirstName: "Hélvio", LastName: "Araújo", Email: "hélvio.araújo@test.it", UserName: "hélvioa", Level: 2},
		{FirstName: "William", LastName: "Walker", Email: "william.walker@test.it", UserName: "williamw", Level: 3},
		{FirstName: "Martin", LastName: "Little", Email: "martin.little@test.it", UserName: "martinl", Level: 2},
		{FirstName: "Daryl", LastName: "Jenkins", Email: "daryl.jenkins@test.it", UserName: "darylj", Level: 2},
		{FirstName: "Noah", LastName: "Andersen", Email: "noah.andersen@test.it", UserName: "noaha", Level: 1},
		{FirstName: "Oliver", LastName: "Savela", Email: "oliver.savela@test.it", UserName: "olivers", Level: 3},
		{FirstName: "Micheal", LastName: "Shelton", Email: "micheal.shelton@test.it", UserName: "micheals", Level: 2},
		{FirstName: "Julius", LastName: "Renner", Email: "julius.renner@test.it", UserName: "juliusr", Level: 3},
		{FirstName: "Silke", LastName: "Rasmussen", Email: "silke.rasmussen@test.it", UserName: "silker", Level: 3},
		{FirstName: "Natalie", LastName: "Zhang", Email: "natalie.zhang@test.it", UserName: "nataliez", Level: 1},
	}
	vulns = []vars.Vulnerability{
		{Name: "DirtyCOW", Cves: []string{"CVE-2016-5195"}, Cvss: 7.8, CorpScore: 8, CvssLink: vars.VarsNullString{sql.NullString{String: "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-5195&vector=AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Valid: true}}, Finder: 1, Initiator: 3, Summary: "This crap is bad!!!", Test: "Look for a cow in the kernel", Mitigation: "Kill it with fire", Dates: vars.VulnDates{Published: vars.VarsNullTime{pq.NullTime{Time: time.Date(2016, time.November, 10, 1, 2, 3, 4, time.UTC), Valid: true}}}, Tickets: []string{"ticket101", "tciket102"}, References: []string{"https://dirtycow.ninja/", "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"}, Exploit: vars.VarsNullString{sql.NullString{String: "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs", Valid: true}}, Exploitable: vars.VarsNullBool{sql.NullBool{Bool: true, Valid: true}}},
		{Name: "Cortana", Cvss: 9.5, CorpScore: 9.0, Finder: 4, Initiator: 4, Summary: "This junk be spying on ya", Test: "Is Windows installed? Yes? Then you have it :(", Mitigation: "Uninstall windows", Tickets: []string{"ticket911"}, References: []string{"https://img.memesuper.com/164df9ae93ae7920d943f86163fa57d1_microsoft-freak-attack-time-meleney-meme_500-375.jpeg"}},
	}
	routerOS = []string{"Alpine Linux", "ClearOS", "DD-WRT", "OpenWall", "OpenWrt", "pfSens", "SonicWALL", "Sophos"}
	serverOS = []string{"Ubuntu 14.04", "Ubuntu 16.04", "CentOS 6", "CentOS 7", "RHEL 7.4", "Debian 8", "Debian 9", "Windows Server 2012 R2"}
	hypervOS = []string{"Proxmox", "XenServer", "Hyper V"}
	location = []string{"corporate", "AWS", "Azure", "Google Cloud"}
	descript = []string{"FTP server", "Mail relay server", "Web Server"}
)

const (
	numSys   = 100
	numVulns = 200
)

func main() {
	config := flag.String("config", "/etc/vars/vars.conf", "The path to the vars configuration file")
	flag.Parse()

	// Read in config and connect to DB
	fmt.Println("[+] Reading vars config file ...")
	err := varsapi.ReadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Connecting to postgresql ...")
	db, err := varsapi.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}

	rand.Seed(time.Now().Unix())

	// Add dummy employees
	fmt.Println("[+] Adding dummy employees ...")
	for _, e := range emps {
		err := varsapi.AddEmployee(db, &e)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}

	// Generate dummy systems
	fmt.Println("[+] Generating dummy systems ...")
	systems := genSystems()

	// Add dummy systems
	fmt.Println("[+] Adding dummy systems ...")
	for _, s := range systems {
		err = varsapi.AddSystem(db, &s)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}

	// Generate dummy vulns
	fmt.Println("[+] Generating dummy vulnerabilities ...")
	genVulns()

	// Add dummy vulns
	fmt.Println("[+] Adding dummy vulnerabilities ...")
	for _, v := range vulns {
		err := varsapi.AddVulnerability(db, &v)
		if !vars.IsNilErr(err) {
			log.Fatal(err)
		}
	}

	// Add some affected systems
	fmt.Println("[+] Adding affected systems ...")
	for _, v := range vulns {
		for _, s := range systems {
			r := random(0, 4)
			if r == 0 {
				sid, err := vars.GetSystemID(s.Name)
				if !vars.IsNilErr(err) {
					log.Fatal(err)
				}
				s.ID = sid
				vid, err := vars.GetVulnID(v.Name)
				if !vars.IsNilErr(err) {
					log.Fatal(err)
				}
				v.ID = vid
				err = varsapi.AddAffected(db, v.ID, s.ID)
				if !vars.IsNilErr(err) {
					log.Fatal(err)
				}
				q := random(0, 2)
				if q == 0 {
					err = varsapi.UpdateAffected(db, v.ID, s.ID, true)
				}
			}
		}
	}

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

	// Close some VAs
	fmt.Println("[+] Closing some VAs ...")
	for i := 0; i < (numVulns / 2); i++ {
		v := int64(random(1, numVulns))
		err = varsapi.CloseVulnerability(db, v)
		if err != nil && !vars.IsNoRowsError(err) {
			log.Fatal(err)
		}
	}

	fmt.Println("[+] Closing connection to postgresql")
	varsapi.CloseDB(db)
}

func genSystems() []vars.System {
	sys := []vars.System{}
	for i := 1; i <= numSys; i++ {
		s := vars.System{}
		r := random(0, 3)
		if r == 0 {
			s.Name = fmt.Sprintf("svr%d", i)
			s.Type = "server"
			s.OpSys = serverOS[random(0, len(serverOS)-1)]
			s.Location = location[random(0, len(location)-1)]
			s.Description = descript[random(0, len(descript)-1)]
		} else if r == 1 {
			s.Name = fmt.Sprintf("hvr%d", i)
			s.Type = "hypervisor"
			s.OpSys = hypervOS[random(0, len(hypervOS)-1)]
			s.Location = location[0]
			s.Description = "Hypervisor server"
		} else {
			s.Name = fmt.Sprintf("rtr%d", i)
			s.Type = "router"
			s.OpSys = routerOS[random(0, len(routerOS)-1)]
			s.Location = location[random(0, len(location)-1)]
			if random(0, 1) == 0 {
				s.Description = fmt.Sprintf("Router %d", i)
			} else {
				s.Description = fmt.Sprintf("Firewall %d", i)
			}
		}
		sys = append(sys, s)
	}
	return sys
}

func genVulns() {
	for i := 3; i <= numVulns; i++ {
		v := vars.Vulnerability{}
		v.Name = fmt.Sprintf("Vuln%d", i)
		numCves := random(0, 10)
		for j := 0; j < numCves; j++ {
			y := random(2000, 2017)
			c := random(1, 9999)
			v.Cves = append(v.Cves, fmt.Sprintf("CVE-%d-%d", y, c))
		}
		f, err := strconv.ParseFloat(fmt.Sprintf("%d.%d", random(0, 9), random(0, 9)), 32)
		if err != nil {
			log.Fatal(err)
		}
		v.Cvss = float32(f)
		f, err = strconv.ParseFloat(fmt.Sprintf("%d.%d", random(0, 9), random(0, 9)), 32)
		if err != nil {
			log.Fatal(err)
		}
		v.CorpScore = float32(f)
		v.Finder = random(1, len(emps)-1)
		v.Initiator = random(1, len(emps)-1)
		v.Summary = fmt.Sprintf("Dummy vulnerability %d", i)
		v.Test = fmt.Sprintf("Test for vulnerability %d", i)
		v.Mitigation = fmt.Sprintf("Mitigation strategy for vulnerability %d", i)
		numTickets := random(0, 10)
		for j := 0; j < numTickets; j++ {
			v.Tickets = append(v.Tickets, fmt.Sprintf("Ticket-%d%d", i, j))
		}
		numRefs := random(0, 10)
		for j := 0; j < numRefs; j++ {
			v.References = append(v.References, fmt.Sprintf("Ref-%d%d", i, j))
		}
		vulns = append(vulns, v)
	}
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}
