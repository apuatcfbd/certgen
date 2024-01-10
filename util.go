package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func writeToFile(path string, content []byte, perm os.FileMode) {
	err := os.WriteFile(path, content, perm)
	failIfErr(err, "Failed to write "+path)
}

func readFromFile(path string) []byte {
	fileBytes, err := os.ReadFile(path)
	failIfErr(err, "File "+path+" read error: ")
	return fileBytes
}

func failIfErr(e error, prependMsg ...string) {
	if e != nil {
		log.Fatalf("%s, Error: %s \n", prependMsg[0], e.Error())
	}
}

func isPathExist(p string) (bool, error) {
	if _, err := os.Stat(p); err != nil {
		return false, err
	}
	return true, nil
}

func readUserInput(msg string) (val string, err error) {
	fmt.Print(msg + ": ")
	r := bufio.NewReader(os.Stdin)
	val, err = r.ReadString('\n')
	val = strings.Trim(val, "\n")
	return
}

type projectInfo struct {
	Name       string
	caKey      string
	caCert     string
	srvKey     string
	srvCertCrt string
	srvCertPem string
	srvCertPfx string
}

func genProjectInfo(projectName string) projectInfo {
	info := projectInfo{}

	// clean name
	replaceChars := map[string]string{
		"\n": "",
		"$":  "",
		"#":  "",
		",":  "",
		";":  "",
		"[":  "",
		"]":  "",
		"{":  "",
		"}":  "",
		"(":  "",
		")":  "",
		"~":  "",
		" ":  "_",
		".":  "-",
	}

	cn := projectName
	for replace, with := range replaceChars {
		cn = strings.ReplaceAll(cn, replace, with)
	}

	info.Name = cn
	info.caKey = cn + "_ca_key.pem"
	info.caCert = cn + "_ca_cert.pem"
	info.srvKey = cn + "_srv_key.pem"
	info.srvCertCrt = cn + "_srv_cert.crt"
	info.srvCertPem = cn + "_srv_cert.pem"
	info.srvCertPfx = cn + "_srv_cert.pfx"

	return info
}
