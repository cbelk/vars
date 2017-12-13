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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	Url       string
	BasicAuth string
}

var conf Config

// Authenticate will send the provided username and password to the LDAP server API defined
// in Config.Url for authentication and return a boolean indicating whether the credentials
// are valid or not.
func Authenticate(username, password string) (bool, error) {
	form := url.Values{}
	form.Set("UserName", username)
	form.Set("Password", password)
	req, err := http.NewRequest("POST", conf.Url, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", conf.BasicAuth))
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return false, errors.New(fmt.Sprintf("Response code is %v", res.StatusCode))
	}
	rb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	if string(rb) == "true" {
		return true, nil
	}
	return false, nil
}

func init() {
	config := os.Getenv("VARS_AUTH_CONFIG")
	if config == "" {
		def := "/etc/vars/ldap.conf"
		if _, err := os.Stat(def); os.IsNotExist(err) {
			log.Fatal("ldap: Cannot find a configuration file (checked VARS_AUTH_CONFIG and /etc/vars/ldap.conf)")
		}
		config = def
	}
	file, err := os.Open(config)
	if err != nil {
		log.Fatal(err)
	}
	err = json.NewDecoder(file).Decode(&conf)
	if err != nil {
		log.Fatal(err)
	}
}
