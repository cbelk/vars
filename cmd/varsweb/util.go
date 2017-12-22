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
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"plugin"
	"strings"
)

type Config struct {
	AuthPlug string
	PlugDir  string
	Port     string
	WebRoot  string
	Skey     string
}

var (
	authenticate func(string, string) (bool, error)
	reports      map[string]*plugin.Plugin
	webConf      Config
	templates    *template.Template
)

// LoadAuth loads the auth plugin and returns the Authenticate function.
func LoadAuth() {
	if webConf.AuthPlug == "" {
		log.Fatal("VarsWeb: LoadAuth: No authentication plugin set in the varsweb config file")
	}
	plugPath := fmt.Sprintf("%s/auth/%s.so", webConf.PlugDir, webConf.AuthPlug)
	plug, err := plugin.Open(plugPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadAuth: Unable to load the authentication plugin at %s. \nThe following error was thrown: %v", plugPath, err))
	}
	symAuth, err := plug.Lookup("Authenticate")
	if err != nil {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadAuth: The following error occured when performing lookup on plugin: %v", err))
	}
	auth, ok := symAuth.(func(string, string) (bool, error))
	if !ok {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadAuth: The following error occured when performing a type assertion: %v", err))
	}
	authenticate = auth
}

// LoadReports loads the report plugins.
func LoadReports() {
	reports = make(map[string]*plugin.Plugin)
	rdir := fmt.Sprintf("%s/report", webConf.PlugDir)
	plugs, err := ioutil.ReadDir(rdir)
	if err != nil {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadReports: The following error occured when retrieving the report plugins: %v", err))
	}
	for _, plug := range plugs {
		pname := plug.Name()
		if strings.HasSuffix(pname, ".so") {
			p, err := plugin.Open(fmt.Sprintf("%s/%s", rdir, pname))
			if err != nil {
				log.Fatal(fmt.Sprintf("VarsWeb: LoadReports: Unable to load the plugin at %s/%s. \nThe following error was thrown: %v", rdir, pname, err))
			}
			rname, err := p.Lookup("Name")
			if err != nil {
				log.Fatal(fmt.Sprintf("VarsWeb: LoadReports: The following error occured when looking up the name for plugin %s/%s: %v", rdir, pname, err))
			}
			rn, ok := rname.(*string)
			if !ok {
				log.Fatal(fmt.Sprintf("VarsWeb: LoadReports: The following error occured when performing a type assertion on name for plugin %s/%s: %v", rdir, pname, err))
			}
			reports[*rn] = p
		}
	}
}

// LoadTemplates loads the html template files.
func LoadTemplates() {
	var tfiles []string
	tdir := fmt.Sprintf("%s/templates", webConf.WebRoot)
	files, err := ioutil.ReadDir(tdir)
	if err != nil {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadTemplates: The following error occured when retrieving the template files: %v", err))
	}
	for _, file := range files {
		fname := file.Name()
		if strings.HasSuffix(fname, ".tmpl") {
			tfiles = append(tfiles, fmt.Sprintf("%s/%s", tdir, fname))
		}
	}
	templates, err = template.ParseFiles(tfiles...)
	if err != nil {
		log.Fatal(fmt.Sprintf("VarsWeb: LoadTemplates: The following error occured when parsing the template files: %v", err))
	}
}

// ReadVarsConfig sets the path to the vars.conf file and passes it to the ReadConfig function of the varsapi
// so that the VARS Config object can be created.
func ReadVarsConfig() {
	config := os.Getenv("VARS_CONFIG")
	if config == "" {
		def := "/etc/vars/vars.conf"
		if _, err := os.Stat(def); os.IsNotExist(err) {
			log.Fatal("VarsWeb: ReadVarsConfig: Cannot find a configuration file (checked VARS_CONFIG and /etc/vars/vars.conf)")
		}
		config = def
	}
	file, err := os.Open(config)
	if err != nil {
		log.Fatal(err)
	}
	err = json.NewDecoder(file).Decode(&Conf)
	if err != nil {
		log.Fatal(err)
	}
}

// ReadWebConfig sets the path to the varsweb.conf file and builds the varsweb Config object with its contents.
func ReadWebConfig() {
	config := os.Getenv("VARS_WEB_CONFIG")
	if config == "" {
		def := "/etc/vars/varsweb.conf"
		if _, err := os.Stat(def); os.IsNotExist(err) {
			log.Fatal("VarsWeb: ReadWebConfig: Cannot find a configuration file (checked VARS_WEB_CONFIG and /etc/vars/varsweb.conf)")
		}
		config = def
	}
	file, err := os.Open(config)
	if err != nil {
		log.Fatal(err)
	}
	err = json.NewDecoder(file).Decode(&webConf)
	if err != nil {
		log.Fatal(err)
	}
}
