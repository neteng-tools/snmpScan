package snmpScan

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
)

const (
	defaultOID     = "1.3.6.1.2.1.1.5.0"
	defaultWalkOID = "1.3.6"
)

type SnmpInput struct {
	Username string
	Priv     string
	Auth     string
	Method   string
	Version  string
	AuthType string
	PrivType string
	Oid      string
	Verbose  bool
	LineSize int
	Config   g.GoSNMP
	PrivMap  map[string]g.SnmpV3PrivProtocol
	AuthMap  map[string]g.SnmpV3AuthProtocol
}

func (input *SnmpInput) Fill_Defaults() {
	input.Oid = defaultOID
	input.Config = g.GoSNMP{
		Port:          161,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Timeout:       1 * time.Second,
	}
	input.PrivMap = map[string]g.SnmpV3PrivProtocol{
		"AES":    g.AES,
		"AES192": g.AES192,
		"AES256": g.AES256C,
	}
	input.AuthMap = map[string]g.SnmpV3AuthProtocol{
		"SHA":    g.SHA,
		"SHA256": g.SHA256,
		"SHA512": g.SHA512,
	}
}

// Processes input provided as 10.0.0.1 or 10.0.0.1-255 or 10.0.0.1,10.0.0.2
func (input *SnmpInput) StartScan(ip string) error {
	count := 0
	var waitGroup sync.WaitGroup
	ipList := strings.Split(ip, ",")

	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		if len(netID) < 3 {
			return fmt.Errorf("provided IP Address is incorrect or malformed. Please retry")
		}
		netRangeSlice := strings.Split(netID[3], "-")
		var netRangeEnd int
		netRangeStart, err := strconv.Atoi(netRangeSlice[0])
		if err != nil {
			return fmt.Errorf("starting IP not valid: %v", err)
		}
		if len(netRangeSlice) == 1 {
			netRangeEnd, err = strconv.Atoi(netRangeSlice[0])
			if err != nil {
				return fmt.Errorf("ending IP not valid: %v", err)
			}
		} else {
			netRangeEnd = netRangeStart
		}

		for i := netRangeStart; i <= netRangeEnd; i++ {
			ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				input.Scanner(ipAddr)
			}()
			if count > 200 { //only allows 200 routines at once. TODO: Needs replaced with real logic at some point to manage snmp connections.
				time.Sleep(time.Duration(500 * time.Millisecond))
				count = 0
			}
			count++
		}
	}
	waitGroup.Wait()
	return nil
}

func (input *SnmpInput) Scanner(target string) {

	var m sync.Mutex
	input.Config.Target = target
	pinger, pingErr := ping.NewPinger(target)
	if pingErr != nil {
		fmt.Println("timed out: " + pingErr.Error())
	}
	pinger.Count = 3
	pinger.SetPrivileged(true)
	pinger.Timeout = 2000 * time.Millisecond
	pinger.Run() // blocks until finished
	stats := pinger.Statistics()
	// get send/receive/rtt stats
	if stats.PacketsRecv == 0 {
		return
	}

	if input.Verbose {
		fmt.Println("SNMP Version: " + input.Version)
	}

	err := input.Config.Connect()
	if err != nil {
		m.Lock()
		defer m.Unlock()
		fmt.Println(target + ": error connecting " + err.Error())
		return
	}
	input.FinishConfig()
	if input.Verbose {
		log.Println("connected to: " + target)
	}
	defer input.Config.Conn.Close()
	if input.Method == "Walk" {
		//basically says to change default if not specified. This OID is currently the default for a Get request. Probably needs to be done better
		if input.Oid == defaultOID {
			input.Oid = defaultWalkOID
		}
		if input.Verbose {
			log.Println("Walking devices from: " + input.Oid)
		}
		var count int
		var walkPayLoad bytes.Buffer
		err := input.Config.Walk(input.Oid, func(pdu g.SnmpPDU) error {
			switch v := pdu.Value.(type) {
			case []byte:
				decodedString := hex.EncodeToString(v)
				var macString string
				if len(decodedString) == 12 {
					for i := 0; i < len(decodedString); i++ {
						if i%2 == 0 && i != 0 {
							macString += ":"
						}
						macString += strings.ToUpper(string(decodedString[i]))

					}
					walkPayLoad.WriteString(pdu.Name)
					walkPayLoad.WriteString(": ")
					walkPayLoad.WriteString(macString)
					walkPayLoad.WriteString("\n")
				} else {
					walkPayLoad.WriteString(pdu.Name + ": " + string(v) + "\n")
				}
			case string:
				walkPayLoad.WriteString(pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(v)
				walkPayLoad.WriteString("\n")
			case uint, uint16, uint64, uint32, int:
				walkPayLoad.WriteString(pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(fmt.Sprint(v) + "\n")
			default:
				walkPayLoad.WriteString("*" + pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(fmt.Sprint(v))
				walkPayLoad.WriteString(reflect.TypeOf(v).Name() + "\n")
			}
			if count > input.LineSize {
				fmt.Println(walkPayLoad.String())
				count = 0
				walkPayLoad.Reset()
			}
			count++
			return nil
		})
		if err != nil {
			fmt.Println("Error walking device: " + err.Error())
			return
		}
		return
	}
	if input.Method == "Get" {
		oids := strings.Split(input.Oid, ",")
		result, err := input.Config.Get(oids)
		if err != nil {
			//ignore devices that aren't needed.
			return
		}
		var rows []string
		for _, variable := range result.Variables {
			if variable.Value != nil {
				switch v := variable.Value.(type) {
				case string:
					rows = append(rows, variable.Value.(string))
				case []uint8:
					decodedString, err := hex.DecodeString(string(v))
					if err != nil {
						rows = append(rows, string(v))
					} else {
						fmt.Println(hex.EncodeToString(decodedString))
					}
				case int:
					rows = append(rows, fmt.Sprint(v))
				default:
					fmt.Println(v)
					rows = append(rows, "Unhandled SNMP output")
				}
			}

		}
		if len(rows) == 1 {
			fmt.Println(rows[0])
		} else {
			m.Lock()
			fmt.Printf("%s,[%v],[%s]\n", target, strings.Join(rows, ":::"), strings.Join(oids, ":::"))
			m.Unlock()
		}
	}

}

// Uses the predetermined version information to finish building the snmp config.
func (input *SnmpInput) FinishConfig() {
	if input.Version == "3" {
		input.Config.Version = g.Version3
		input.Config.SecurityParameters = &g.UsmSecurityParameters{
			UserName:                 input.Username,
			AuthenticationProtocol:   input.AuthMap[input.AuthType],
			AuthenticationPassphrase: input.Auth,
			PrivacyProtocol:          input.PrivMap[input.PrivType],
			PrivacyPassphrase:        input.Priv,
		}
	} else if input.Version == "2c" {
		input.Config.Version = g.Version2c
		input.Config.Community = input.Username
	} else {
		input.Config.Version = g.Version1
		input.Config.Community = input.Username
	}
}
