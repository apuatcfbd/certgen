package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
)

var configFilePath = "./config.yml"

type caInfo struct {
	Organization  string `yaml:"organization"`
	Country       string `yaml:"country"`
	Locality      string `yaml:"city"`
	StreetAddress string `yaml:"street"`
	PostalCode    string `yaml:"postalCode"`
}

type caConfig struct {
	Key         string `yaml:"privateKeyPath"`
	Serial      int    `yaml:"serial"`
	ExpiryYears int    `yaml:"expiryYears"`
	Info        caInfo
}

type serverInfo struct {
	Organization  string `yaml:"organization"`
	Country       string `yaml:"country"`
	Locality      string `yaml:"city"`
	StreetAddress string `yaml:"street"`
	PostalCode    string `yaml:"postalCode"`
	CommonName    string `yaml:"domainName"`
}

type serverConfig struct {
	CaCert string `yaml:"caCertificatePath"`
	CaKey  string `yaml:"caPrivateKeyPath"`
	Key    string `yaml:"privateKeyPath"`

	Serial      int `yaml:"serial"`
	ExpiryYears int `yaml:"expiryYears"`
	Info        serverInfo
	IpAddress   string `yaml:"ipAddress"`
	// encryption password
	Password string `yaml:"password"`
}

type config struct {
	// will be used as dir & file name
	ProjectName string `yaml:"projectName"`
	// generate CA & use that to issue server cert
	GenCA  bool `yaml:"genCA"`
	Ca     caConfig
	Server serverConfig
}

func (c *config) Parse() {
	if exists, _ := isPathExist(configFilePath); !exists {
		log.Fatalln("Config file unavailable at " + configFilePath)
	}

	fb, err := os.ReadFile(configFilePath)
	failIfErr(err)

	unmarshalErr := yaml.Unmarshal(fb, c)
	failIfErr(unmarshalErr)
}

func generateEmptyConfigFile() {

	if exists, _ := isPathExist(configFilePath); exists {
		input, err := readUserInput("Config file exist, overwrite? [y/N]")
		failIfErr(err, "Failed to read your input")

		input = strings.ToLower(input)

		if input == "n" {
			fmt.Println("Cancelled!")
			return
		}
	}

	// generated project info
	pi := genProjectInfo("example.com")

	c := config{
		ProjectName: "example.com",
		GenCA:       true,
		Ca: caConfig{
			Key: pi.caKey,

			Serial:      2020,
			ExpiryYears: 10,
			Info: caInfo{
				Organization:  "Snebtaf",
				Country:       "UK",
				Locality:      "London",
				StreetAddress: "Bricklane",
				PostalCode:    "E1 6QL",
			},
		},
		Server: serverConfig{
			CaKey:  pi.caKey,
			CaCert: pi.caCert,
			Key:    pi.srvKey,

			Serial:      2021,
			ExpiryYears: 5,
			Info: serverInfo{
				Organization:  "Ordering2online",
				Country:       "BD",
				Locality:      "Sylhet",
				StreetAddress: "Ambarkhana",
				PostalCode:    "1201",
				CommonName:    "print.digitafact.com",
			},
			IpAddress: "192.168.0.121",
			Password:  "1234",
		},
	}

	ymlData, err := yaml.Marshal(&c)
	failIfErr(err)

	writeToFile(configFilePath, ymlData, 0600)
}
