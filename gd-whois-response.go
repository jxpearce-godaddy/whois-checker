package main

import "encoding/xml"

type GDWhoisResponse struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    struct {
		GetParsedWhoisResponse struct {
			GetParsedWhoisResult string `xml:"GetParsedWhoisResult"`
		} `xml:"GetParsedWhoisResponse"`
	} `xml:"Body"`
}

type GDWhois struct {
	XMLName xml.Name `xml:"whois"`
	Success string   `xml:"success"`
	Domain  struct {
		Name             string `xml:"name"`
		PrivateLabelId   string `xml:"privateLabelId"`
		Whoisserver      string `xml:"whoisserver"`
		Registrar        string `xml:"registrar"`
		WhoisRegistrarID string `xml:"whoisregistrarid"`
		Dates            []struct {
			Type string `xml:"type,attr"`
			Date string `xml:",chardata"`
		} `xml:"dates>date"`
		RegistrationDate string
		ExpirationDate   string
		Nameservers      []string `xml:"nameservers>nameserver"`
		Statuses         []string `xml:"statuses>status"`
		Available        string   `xml:"available"`
		Contacts         []struct {
			Type       string   `xml:"type,attr"`
			Roid       string   `xml:"roid"`
			FirstName  string   `xml:"firstname"`
			LastName   string   `xml:"lastname"`
			Company    string   `xml:"company"`
			Address    []string `xml:"addresses>address"`
			City       string   `xml:"city"`
			State      string   `xml:"state"`
			Postalcode string   `xml:"postalcode"`
			Country    string   `xml:"country"`
			Phone      string   `xml:"phone"`
			Fax        string   `xml:"fax"`
			Email      string   `xml:"email"`
		} `xml:"contacts>contact"`
	} `xml:"domain"`
}
