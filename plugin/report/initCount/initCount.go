package main

import (
	"fmt"

	"github.com/cbelk/vars/pkg/varsapi"
)

var Name string = "VA Initiated Count"

func GenerateReport() (string, error) {
	html := `
            <div class="table-responsive">
            <table class="table table-striped table-dark table-bordered table-hover" id="init-table">
                <thead>
                    <tr>
                        <th scope="col" class="col-3" onclick="sortTable('init-table', 0)">Name</th>
                        <th scope="col" class="col-3" onclick="sortTable('init-table', 1)">Number of VAs initiated</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
            </div>
            `

	initiator := make(map[int64]int)
	vulns, err := varsapi.GetVulnerabilities()
	if !varsapi.IsNilErr(err) {
		return "", err
	}
	for _, vuln := range vulns {
		_, ok := initiator[vuln.Initiator]
		if ok {
			initiator[vuln.Initiator] += 1
		} else {
			initiator[vuln.Initiator] = 1
		}
	}
	s := ""
	for init, cnt := range initiator {
		emp, err := varsapi.GetEmployeeByID(init)
		if !varsapi.IsNilErr(err) {
			return "", err
		}
		s += fmt.Sprintf("<tr><td>%s %s</td><td>%d</td></tr>", emp.FirstName, emp.LastName, cnt)
	}
	return fmt.Sprintf(html, s), nil
}
