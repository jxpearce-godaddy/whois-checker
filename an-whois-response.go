package main

import (
	"encoding/xml"
)

type ANWhoisResponse struct {
	XMLName      xml.Name `xml:"result"`
	ResultStatus string   `xml:"resultStatus"`
	Whois        *ANWhois `xml:"whois"`
}

type ANWhois struct {
	XMLName      xml.Name `xml:"whois"`
	ResultStatus struct {
		Code        string `xml:"code,attr"`
		Description string `xml:",chardata"`
	} `xml:"resultStatus"`
	Registrar         string   `xml:"registrar"`
	Whoisserver       string   `xml:"whoisServer"`
	RegistrationDate  string   `xml:"registrationDate"`
	ExpirationDate    string   `xml:"expirationDate"`
	Nameservers       []string `xml:"nameServer"`
	Statuses          []string `xml:"domainStatus"`
	Registrant        string   `xml:"domaregistrantnStatus"`
	AdminEmail        string   `xml:"adminEmail"`
	AdminPhone        string   `xml:"adminPhone"`
	RegistrantContact string   `xml:"registrantContact"`
	AdminContact      string   `xml:"adminContact"`
	BillingContact    string   `xml:"billingContact"`
	TechContact       string   `xml:"techContact"`
}
