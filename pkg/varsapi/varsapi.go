package varsapi

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/cbelk/vars"
)

func GetVulnerability(id string) ([]byte, error) {
	vid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}
	vuln, err := vars.GetVulnerability(vid)
	if err != nil {
		return nil, err
	}
	return json.Marshall(vuln)
}

func UpdateVulnerability(db *sql.DB, v url.Values) error {
	// Get the vulnid
	id := v.Get("vulnid")
	if id == "" {
		return errors.New("UpdateVulnerability: Error: No vulnid in request")
	}
	vid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	//Start transaction and set rollback function
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			tx.Rollback()
		}
	}()

	// Update vulnname
	if vname := v.Get("vulnname"); vname != "" {
		err = vars.UpdateVulnName(tx, vid, vname)
		if err != nil {
			return err
		}
	}

	// Update CVE

	rollback = false
	if e := tx.Commit(); e != nil {
		return e
	}
	return nil
}
