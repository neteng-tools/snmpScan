package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"sync"

	"github.com/neteng-tools/snmpScan/pkg/Scanner"
)

func main() {
	var snmp snmpScan.SnmpInput
	var waitGroup sync.WaitGroup
	snmp.Fill_Defaults()

	ipAddExp := flag.String("t", "", "Define target devices. (-t 10.0.0.1 or -t 10.0.0.1-100 or -t 10.0.0.1,10.0.0.2)")
	snmp.Method = flag.String("m", *snmp.Method, "Set snmp method.\n\t-m Get\n\t-m Walk   A walk is limited to a single IP")
	version := flag.String("v", snmp.Version, "Set snmp version.\n\t-v 1\n\t-v 2c\n\t-v 3")
	privType := flag.String("pt", snmp.PrivType, "Enter SNMPv3 Priv Type.\n\t-pt AES\n\t-pt AES192\n\t-pt AES256")
	authType := flag.String("at", snmp.AuthType, "Enter SNMPv3 Auth Type.\n\t-at SHA\n\t-at SHA256\n\t-at SHA512")
	oid := flag.String("o", snmp.Oid, `Enter OIDs to grab separated by a comma. You can also use this for a Walk (walk default "1.3.6")`)
	snmp.Verbose = flag.Bool("vv", *snmp.Verbose, "Enable verbose output\n\nEx: .\\snmpCLI.exe -t 10.0.0.0-150 -c v3User -m Get -v 3 -p PrivPass -pt AES256 -a AuthPass -at SHA512 -o 1.3.6.1.2.1.1.1.0")
	lineSize := flag.Int("n", snmp.LineSize, "Specifies lines to print during a walk. Lower number results in faster response, but slower walk. \nHigher number reduces the overall time a walk takes. Use more than 1000 if you're redirecting output to a file.\n\t-n 50\n\t-n 1000")
	username := flag.String("c", snmp.Username, "Set snmp community string or v3 User Name.\n\t-c v3User")
	auth := flag.String("a", "", "Provide Authentication Password")
	priv := flag.String("p", "", "Provide Privacy Password")

	flag.Parse()
	if *ipAddExp == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}
	snmp.Oid, snmp.PrivType, snmp.AuthType, snmp.LineSize, snmp.Username = *oid, *privType, *authType, *lineSize, *username
	snmp.Auth, snmp.Priv, snmp.Version = *auth, *priv, *version
	start := time.Now()
	output := make(chan snmpScan.Response)
	info := make(chan string)

	go func() {
		count := 0

		var walkPayLoad bytes.Buffer
		var oidList []string
		var values []string
		for out := range output{
			for oid, value := range out.Value {
				if *snmp.Method == "Walk" {
					walkPayLoad.WriteString(oid)
					walkPayLoad.WriteString(": ")
					walkPayLoad.WriteString(value)
					walkPayLoad.WriteString("\n")
					if count >= 200 {
						fmt.Println(walkPayLoad.String())
						count = 0
						walkPayLoad.Reset()
					}
				count++
				}
				if *snmp.Method == "Get" {
					oidList = append(oidList, oid)
					values = append(values, value)
				}
			}
			if *snmp.Method == "Get" {
				fmt.Printf("%s,[%v],[%s]\n", out.IP, strings.Join(values, ":::"), strings.Join(oidList, ":::"))
			}
		}
	}()


	err := snmp.StartScan(*ipAddExp, output, info, &waitGroup)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}

	
	//cli output format for a walk request
	
	waitGroup.Wait()
	close(output)
	duration := time.Since(start)
	if *snmp.Verbose {
		log.Print(duration)
	}
}
