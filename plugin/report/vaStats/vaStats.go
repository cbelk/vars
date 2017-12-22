package main

import (
	"fmt"
	"time"

	"github.com/cbelk/vars/pkg/varsapi"
)

var Name string = "VA Stats"

func GenerateReport() (string, error) {
	html := `
            <div class="table-responsive">
            <table class="table table-striped table-dark table-bordered table-hover" id="num-table">
                <thead>
                    <tr>
                        <th scope="col" class="col-3" onclick="sortTable('num-table', 0)">Count Open</th>
                        <th scope="col" class="col-3" onclick="sortTable('num-table', 1)">Count Closed</th>
                        <th scope="col" class="col-3" onclick="sortTable('num-table', 2)">Average Time Open (days)</th>
                        <th scope="col" class="col-3" onclick="sortTable('num-table', 3)">Longest Time Open (days)</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
            </div>
            `

	open := 0
	closed := 0
	avg := 0.0
	longest, err := time.ParseDuration("0ns")
	if err != nil {
		return "", err
	}
	vulns, err := varsapi.GetVulnerabilities()
	if !varsapi.IsNilErr(err) {
		return "", err
	}
	for _, vuln := range vulns {
		var d time.Duration
		if vuln.Dates.Mitigated.Valid {
			closed++
			d = vuln.Dates.Mitigated.Time.Sub(vuln.Dates.Initiated)
		} else {
			open++
			d = time.Now().Sub(vuln.Dates.Initiated)
		}
		hrs := d.Hours()
		avg += hrs
		if d > longest {
			longest = d
		}
	}
	avg = (avg / float64(len(vulns)))
	adays := (avg / float64(24))
	l := longest.Hours()
	ldays := (l / float64(24))
	s := fmt.Sprintf("<tr><td>%d</td><td>%d</td><td>%f</td><td>%f</td></tr>", open, closed, adays, ldays)
	return fmt.Sprintf(html, s), nil
}
