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
	webConf      Config
	templates    *template.Template
)

// LoadAuth loads the auth plugin and returns the Authenticate function.
func LoadAuth() {
	if webConf.AuthPlug == "" {
		log.Fatal("VarsWeb: LoadAuth: No authentication plugin set in the varsweb config file")
	}
	plugPath := fmt.Sprintf("%s%s.so", webConf.PlugDir, webConf.AuthPlug)
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
