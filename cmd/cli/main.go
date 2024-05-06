package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/neteng-tools/snmpScan/pkg/Scanner"
)

func main() {
	var snmp snmpScan.SnmpInput
	snmp.Fill_Defaults()

	ipAddExp := flag.String("t", "", "Define target devices. (-t 10.0.0.1 or -t 10.0.0.1-100 or -t 10.0.0.1,10.0.0.2)")
	snmp.Method = *flag.String("m", "Get", "Set snmp method.\n\t-m Get\n\t-m Walk   A walk is limited to a single IP")
	snmp.Version = *flag.String("v", "3", "Set snmp version.\n\t-v 1\n\t-v 2c\n\t-v 3")
	snmp.PrivType = *flag.String("pt", "AES", "Enter SNMPv3 Priv Type.\n\t-pt AES\n\t-pt AES192\n\t-pt AES256")
	snmp.AuthType = *flag.String("at", "SHA", "Enter SNMPv3 Auth Type.\n\t-at SHA\n\t-at SHA256\n\t-at SHA512")
	snmp.Oid = *flag.String("o", snmp.Oid, `Enter OIDs to grab separated by a comma. You can also use this for a Walk (walk default "1.3.6")`)
	snmp.Verbose = *flag.Bool("vv", false, "Enable verbose output\n\nEx: .\\snmpCLI.exe -t 10.0.0.0-150 -c v3User -m Get -v 3 -p PrivPass -pt AES256 -a AuthPass -at SHA512 -o 1.3.6.1.2.1.1.1.0")
	snmp.LineSize = *flag.Int("n", 50, "Specifies lines to print during a walk. Lower number results in faster response, but slower walk. \nHigher number reduces the overall time a walk takes. Use more than 1000 if you're redirecting output to a file.\n\t-n 50\n\t-n 1000")
	snmp.Username = *flag.String("c", "public", "Set snmp community string or v3 User Name.\n\t-c v3User")
	snmp.Auth = *flag.String("a", "", "Provide Authentication Password")
	snmp.Priv = *flag.String("p", "", "Provide Privacy Password")

	flag.Parse()
	if *ipAddExp == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}
	start := time.Now()
	err := snmp.StartScan(*ipAddExp)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	duration := time.Since(start)
	if snmp.Verbose {
		log.Print(duration)
	}
}
