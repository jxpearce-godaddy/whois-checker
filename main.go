package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

var StatusCodes = []string{
	"addperiod",
	"autorenewperiod",
	"inactive",
	"ok",
	"pendingcreate",
	"pendingdelete",
	"pendingrenew",
	"pendingrestore",
	"pendingtransfer",
	"pendingupdate",
	"redemptionperiod",
	"renewperiod",
	"serverdeleteprohibited",
	"serverhold",
	"serverrenewprohibited",
	"servertransferprohibited",
	"serverupdateprohibited",
	"transferperiod",
	"clientdeleteprohibited",
	"clienthold",
	"clientrenewprohibited",
	"clienttransferprohibited",
	"clientupdateprohibited",
}

type VerboseOptions = struct {
	Verbose     bool
	PrintParsed bool
	RawAfternic bool
	RawGodaddy  bool
}

const whoisFileName = "check.csv"

func main() {

	domain := flag.String("d", "", "domain to check")
	domainList := flag.String("f", "", "file containing domain list")
	verbose := flag.Bool("v", false, "verbose mode")
	printParsed := flag.Bool("p", false, "print parsed structs")
	printAfternic := flag.Bool("ra", false, "print raw afternic result")
	printGodaddy := flag.Bool("rg", false, "print raw godaddy result")
	recheck := flag.Bool("ch", false, "recheck failed domains from whois.csv")

	flag.Parse()

	verboseOptions := VerboseOptions{
		*verbose,
		*printParsed,
		*printAfternic,
		*printGodaddy,
	}

	if *domain != "" {
		anErrors, gdErrors := checkDomain(*domain, verboseOptions, true, true)
		if len(anErrors) > 0 || len(gdErrors) > 0 {
			if *verbose == true {
				fmt.Printf("%s: AN errors %s\n", *domain, anErrors)
				fmt.Printf("%s: GD errors %s\n", *domain, gdErrors)

			}
			os.Exit(-1)
		}
		if *verbose == true {
			fmt.Printf("%s: Whois responses are the same\n", *domain)
		}
	} else if *recheck {

		recheckDomainList(whoisFileName, verboseOptions)

	} else if *domainList != "" {
		allOK := checkDomainList(*domainList, whoisFileName, verboseOptions)
		if allOK {
			fmt.Println("All domains in list match")
		} else {
			fmt.Println("At least one domain didn't match (check output for details)")
			os.Exit(-2)
		}
	}
}

func recheckDomainList(whoisCheckFile string, verboseOptions VerboseOptions) {

	checkFileIn, err := os.OpenFile(whoisCheckFile, os.O_RDONLY, 0644)
	if err != nil {
		log.Fatalf("unable to open intput file: %v", err)
	}

	outputFileName := whoisCheckFile + ".tmp"

	checkFileOut, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("unable to open output file: %v", err)
	}

	// Read/write the header line
	scanner := bufio.NewScanner(checkFileIn)
	scanner.Scan()
	checkFileOut.WriteString(fmt.Sprintf("%s\n", scanner.Text()))

	// Reprocess any failed calls
	for scanner.Scan() {
		values := strings.Split(scanner.Text(), ",")
		anOK := len(values) > 1 && values[1] == "true"
		gdOK := len(values) > 2 && values[2] == "true"
		anErrors := []string{}
		gdErrors := []string{}
		if !anOK || !gdOK {
			anErrors, gdErrors = checkDomain(values[0], verboseOptions, !anOK, !gdOK)
			anOK = len(anErrors) == 0
			gdOK = len(gdErrors) == 0

		} else {
			fmt.Printf("Not rechecking domain %s\n", values[0])

		}
		checkFileOut.WriteString(fmt.Sprintf("%s,%t,%t,%s,%s\n", values[0], anOK, gdOK, strings.Join(anErrors, ";"), strings.Join(gdErrors, ";")))

	}
	checkFileIn.Close()
	checkFileOut.Close()

	os.Remove(whoisCheckFile)
	os.Rename(outputFileName, whoisCheckFile)
}

func checkDomainList(filePath string, outputFileName string, verboseOptions VerboseOptions) bool {

	allOK := true

	fmt.Println("checking domains listed in ", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("unable to open file: %v", err)
	}
	defer file.Close()

	outputFile, err := os.OpenFile(outputFileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("unable to open file: %v", err)
	}
	defer outputFile.Close()

	outputFile.WriteString("Domain,AN Pass,GD Pass,AN Errors, GD Errors\n")

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain != "" {
			anErrors, gdErrors := checkDomain(domain, verboseOptions, true, true)
			anOK := len(anErrors) == 0
			gdOK := len(gdErrors) == 0
			allOK = allOK && anOK && gdOK
			outputFile.WriteString(fmt.Sprintf("%s,%t,%t,%s,%s\n", domain, anOK, gdOK, strings.Join(anErrors, ";"), strings.Join(gdErrors, ";")))
		}
	}

	return allOK
}

func checkDomain(domain string, verboseOptions VerboseOptions, checkAN bool, checkGD bool) ([]string, []string) {

	if verboseOptions.Verbose {
		fmt.Printf("Checking domain %s - check AN=%t, check GD=%t\n", domain, checkAN, checkGD)
	}

	var anErrors []string = []string{}
	var gdErrors []string = []string{}

	if checkAN {
		anWhois := getAfternicWhois(domain, verboseOptions)

		if verboseOptions.PrintParsed {
			fmt.Printf("AN: %+v\n", anWhois)
		}
		if anWhois != nil {
			anErrors = checkWhois(anWhois.Registrar, anWhois.RegistrationDate, anWhois.ExpirationDate)
			if len(anErrors) == 0 {
				fmt.Printf("************** AN Recheck for %s passed ************** \n", domain)
			}
		} else {
			anErrors = append(anErrors, "NO RESULT")
		}
		if verboseOptions.Verbose {
			fmt.Printf("%s result for AN %t\n", domain, len(anErrors) == 0)
		}
	}
	if checkGD {
		gdWhois := getGDWhois(domain, verboseOptions)

		if verboseOptions.PrintParsed {
			fmt.Printf("GD: %+v\n", gdWhois)
		}
		if gdWhois != nil {
			gdErrors = checkWhois(gdWhois.Domain.Registrar, gdWhois.Domain.RegistrationDate, gdWhois.Domain.ExpirationDate)
			if len(gdErrors) == 0 {
				fmt.Printf("************** GD Recheck for %s passed ************** \n", domain)
			}
		} else {
			gdErrors = append(gdErrors, "NO RESULT")
		}
		if verboseOptions.Verbose {
			fmt.Printf("%s result for GD %t\n", domain, len(gdErrors) == 0)
		}
	}

	return anErrors, gdErrors

}

func checkWhois(registrar string, registrationDate string, expireDate string) []string {
	var result []string = []string{}

	if registrar == "" {
		result = append(result, "REGISTRAR")
	}
	if registrationDate == "" {
		result = append(result, "REG_DATE")
	}
	if expireDate == "" {
		result = append(result, "EXP_DATE")
	}

	return result
}

func getAfternicWhois(domain string, verboseOptions VerboseOptions) *ANWhois {
	url := fmt.Sprintf("http://ace.prod.afternic.com/svcs-ace-whois/restful/whois/realtime/%s", domain)
	resp, err := http.Get(url)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	respBody, _ := ioutil.ReadAll(resp.Body)

	if verboseOptions.RawAfternic {
		fmt.Println("\n\nRaw Whois response from Afternic:\n------------------------------------------------------------------------------------")
		fmt.Println(string(respBody))
	}

	// fmt.Println(string(respBody))

	var whoisResponse ANWhoisResponse
	err = xml.Unmarshal(respBody, &whoisResponse)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// fmt.Printf("%+v\n", whoisResponse)

	return whoisResponse.Whois
}

func getGDWhois(domain string, verboseOptions VerboseOptions) *GDWhois {
	postBodyString := fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Body>
    <GetParsedWhois xmlns="RegistryWhoisWebSvc">
      <sDomainName>%s</sDomainName>
    </GetParsedWhois>
  </soap:Body>
</soap:Envelope>`,
		domain,
	)

	postBody := bytes.NewBuffer([]byte(postBodyString))
	req, _ := http.NewRequest(http.MethodPost, "https://registrywhois.iad2.int.godaddy.com/registrywhoiswebsvc/RegistryWhoisWebSvc.svc", postBody)

	req.Header.Set("Content-Type", "text/xml;charset=utf-8")
	req.Header.Set("SOAPAction", "RegistryWhoisWebSvc/IRegistryWhoisWebSvc/GetParsedWhois")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	respBody, _ := ioutil.ReadAll(resp.Body)

	if verboseOptions.RawGodaddy {
		fmt.Println("\n\nRaw Whois response from GoDaddy:\n------------------------------------------------------------------------------------")
		fmt.Println(string(respBody))
	}

	var whoisResponse GDWhoisResponse
	err = xml.Unmarshal(respBody, &whoisResponse)
	if err != nil {
		fmt.Printf("Error unmarshalling GDWhoisResponse: %s\n", err)
		return nil
	}

	var whois GDWhois
	err = xml.Unmarshal([]byte(whoisResponse.Body.GetParsedWhoisResponse.GetParsedWhoisResult), &whois)

	if err != nil {
		fmt.Printf("Error unmarshalling GDWhois: %s\n", err)
		return nil
	}

	for _, date := range whois.Domain.Dates {
		if date.Type == "create" {
			whois.Domain.RegistrationDate = date.Date
		} else if date.Type == "expire" {
			whois.Domain.ExpirationDate = date.Date
		}
	}

	return &whois
}

func unenscapeString(in string) string {
	out, _ := url.PathUnescape(in)
	out = strings.ReplaceAll(out, "+", " ")

	return out
}

func compareWhois(domain string, anWhois *ANWhois, gdWhois *GDWhois, verboseOptions VerboseOptions) bool {

	if anWhois.ResultStatus.Code == "-1" && gdWhois.Success == "false" {
		// Not found in both
		return true
	}

	gdReg := unenscapeString(gdWhois.Domain.Registrar)
	anReg := unenscapeString(anWhois.Registrar)
	if anReg == "GoDaddy" {
		anReg = "GoDaddy.com, LLC"
	}

	if anReg != gdReg {
		fmt.Printf("Error %s: registrar not the same\n    AN: %s\n    GD: %s\n", domain, anReg, gdReg)
		return false
	}
	if len(gdWhois.Domain.Dates) > 0 &&
		!compareDates(anWhois.RegistrationDate, gdWhois.Domain.Dates[0].Date) {
		fmt.Printf("Error %s: registration dates not the same\n    AN: %s\n    GD: %s\n", domain, anWhois.RegistrationDate, gdWhois.Domain.Dates[0].Date)
		return false
	}
	if len(gdWhois.Domain.Dates) > 1 &&
		!compareDates(anWhois.ExpirationDate, gdWhois.Domain.Dates[1].Date) {
		fmt.Printf("Error: %s expiration dates not the same\n    AN: %s\n    GD: %s\n", domain, anWhois.ExpirationDate, gdWhois.Domain.Dates[1].Date)
		return false
	}
	if !compareStatus(anWhois.Statuses, gdWhois.Domain.Statuses, verboseOptions) {
		fmt.Printf("Error %s: statuses are not the same\n", domain)
		fmt.Printf("    AN Statuses: %v\n", anWhois.Statuses)
		fmt.Printf("    GD Statuses: %v\n", gdWhois.Domain.Statuses)
		return false
	}

	return true
}

func compareDates(anDate string, gdDate string) bool {
	anParsedDate, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", anDate)
	gdParsedDate, _ := time.Parse("01/02/2006 15:04:05", gdDate)

	anYYMMDD := fmt.Sprintf("%04d%02d%02d", anParsedDate.Year(), anParsedDate.Month(), anParsedDate.Day())
	gdYYMMDD := fmt.Sprintf("%04d%02d%02d", gdParsedDate.Year(), gdParsedDate.Month(), gdParsedDate.Day())

	return anYYMMDD == gdYYMMDD
}

func compareStatus(anStatuses []string, gdStatuses []string, verboseOptions VerboseOptions) bool {

	if anStatuses == nil && gdStatuses == nil {
		return true
	}

	filtedAnStatus := []string{}
	filteredGdStatus := []string{}

	// AN status sometimes contains links, e.g.
	for _, status := range anStatuses {

		anStatusWords := strings.Split(status, " ")

		if slices.Contains(StatusCodes, strings.ToLower(anStatusWords[0])) {
			filtedAnStatus = append(filtedAnStatus, anStatusWords[0])
		} else {
			fmt.Printf("  -- Ignoring invalid status '%s'\n", status)
		}
	}
	for _, status := range gdStatuses {
		if slices.Contains(StatusCodes, strings.ToLower(status)) {
			filteredGdStatus = append(filteredGdStatus, status)
		} else {
			fmt.Printf("  -- Ignoring invalid status '%s'\n", status)
		}
	}

	if len(anStatuses) != len(gdStatuses) {
		return false
	}
	sort.Strings(filtedAnStatus)
	sort.Strings(filteredGdStatus)

	for i, anStatus := range filtedAnStatus {
		if anStatus != filteredGdStatus[i] {
			return false
		}
	}
	return true
}
