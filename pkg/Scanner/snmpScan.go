package snmpScan

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
)

type SnmpInput struct {
	Username string
	Priv     string
	Auth     string
	Method   *string
	Version  string
	AuthType string
	PrivType string
	Oid      string
	Verbose  *bool
	LineSize int
	Config   g.GoSNMP
	PrivMap  map[string]g.SnmpV3PrivProtocol
	AuthMap  map[string]g.SnmpV3AuthProtocol
}

type snmpOutput struct{
	IP string
	Value map[string]string
	Log string
}

type Response struct{
	IP string
	Value map[string]string
}


const (
	defaultOID string     = "1.3.6.1.2.1.1.5.0"
	defaultWalkOID string = "1.3.6"
)


func (input *SnmpInput) Fill_Defaults() {
	input.Verbose = new(bool)
	input.Method = new(string)
	input.Oid = defaultOID
	*input.Method = "Get"
	input.Version = "3"
	input.PrivType = "AES"
	input.AuthType = "SHA"
	*input.Verbose = false
	input.LineSize = 50
	input.Username = "public"
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
func (input *SnmpInput) StartScan(ip string, respChan chan Response, info chan string, waitGroup *sync.WaitGroup) error {
	count := 0
	pingTimeout := 2000

	ipList := strings.Split(ip, ",")
	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		//simple check that this is an IP. If split on the dot we should always have 4 octets 10.0.0.1-150 > [10 0 0 1-150]
		if len(netID) <= 3 {
			return fmt.Errorf("provided IP Address is incorrect or malformed. Please retry")
		}
		netRangeSlice := strings.Split(netID[3], "-")
		if *input.Method == "Walk" {
			//makes sure we're not using an ip range. 1-150 > len([1 150]) > 1
			if len(netRangeSlice) == 1 {
				//if we're a good IP and don't have a range on the end, pass the original IP.
				if input.isOnline(ipGate, pingTimeout){
					return input.Scanner(ipGate, respChan, info)
				}
			} else {
				return fmt.Errorf("too many IPs provided for a Walk. Please retry with a single IP")
			}
		} else if *input.Method == "Get" {
			var netRangeEnd int
			netRangeStart, err := strconv.Atoi(netRangeSlice[0])
				fmt.Println(netRangeSlice)
			if err != nil {
				return  fmt.Errorf("starting IP not valid: %v", err)
			}
			if len(netRangeSlice) == 2 {
				netRangeEnd, err = strconv.Atoi(netRangeSlice[1])
				if err != nil {
					return  fmt.Errorf("ending IP not valid: %v", err)
				}
			} else {
				netRangeEnd = netRangeStart
			}
			for i := netRangeStart; i <= netRangeEnd; i++ {
				ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
				waitGroup.Add(1)
				go func(ipAddress string, respChan chan Response, info chan string) {
					defer waitGroup.Done()
					if input.isOnline(ipAddress, pingTimeout){
						input.Scanner(ipAddress, respChan, info)
					} else {
						if *input.Verbose{
							fmt.Printf("%v status is %v\n", ipAddress, input.isOnline(ipAddress, pingTimeout))
						}
					}
				}(ipAddr, respChan, info)
				if count >= 200 { //only allows 200 routines at once. TODO: Needs replaced with real logic at some point to manage snmp connections.
					time.Sleep(time.Duration(500 * time.Millisecond))
					count = 0
				}
				count++
			}
			
		} else {
			return fmt.Errorf("method not defined")
		}
	}
	return nil
}

//pings the device and returns true if its online. If not it returns false even on error
func (input *SnmpInput) isOnline(target string, timeout int) bool {
	pinger, pingErr := ping.NewPinger(target)
	if pingErr != nil {
		fmt.Println(pingErr.Error())
		return false
	}
	pinger.Count = 3
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(timeout) * time.Millisecond
	pinger.Run() // blocks until finished
	stats := pinger.Statistics()
	fmt.Print(stats.PacketsRecv)
	// get send/receive/rtt stats
	return stats.PacketsRecv > 0
}

func (input *SnmpInput) Scanner(target string, response chan Response, info chan string) error {
	resp := new(Response)
	resp.Value = make(map[string]string)
	var m sync.Mutex
	input.Config.Target = target
	resp.IP = target

	if *input.Verbose {
		info <- fmt.Sprintf("SNMP Version: %v", *input.Method)
	}
	err := input.Config.Connect()
	if err != nil {
		m.Lock()
		defer m.Unlock()
		return fmt.Errorf("snmp failed: error connecting %v", err.Error())
	}
	input.FinishConfig()
	if *input.Verbose {
		info <- fmt.Sprintf("connected to: %v", target)
	}
	defer input.Config.Conn.Close()
	if *input.Method == "Walk" {
		//basically says to change default if not specified. This OID is currently the default for a Get request. Probably needs to be done better
		if input.Oid == defaultOID {
			input.Oid = defaultWalkOID
		}
		if *input.Verbose {
			info <- fmt.Sprintf("Walking devices from: %v", input.Oid)
		}
		err := input.Config.Walk(input.Oid, func(pdu g.SnmpPDU) error {
			go func(){
				value, ok := input.getValue(pdu.Value)
				if ok {
					m.Lock()
					defer m.Unlock()
					resp.Value[input.Oid] = value
					response <- *resp
				}
			}()
			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking device: %v", err.Error())
		}
		return nil
	}
	if *input.Method == "Get" {
		oids := strings.Split(input.Oid, ",")
		result, err := input.Config.Get(oids)
		
		if err != nil {
			//ignore devices that aren't needed.
			return nil
		}
		for _, variable := range result.Variables {
			if variable.Value != nil {
				value, ok := input.getValue(variable.Value)
				if ok && value != "" {
					if !*input.Verbose {
						fmt.Println(value)
					}
					resp.Value[input.Oid] = value
				}
			}

		}
		response <- *resp
		return nil
		
	}
	return nil
}

//processes oid return value and tries to convert it to a string. Bool is set to false if we couldn't determine the type.
func (input *SnmpInput) getValue(value any) (string, bool) {
	switch v := value.(type) {
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
			return macString, true
		} else {
			return string(v), true
		}
	case string:
		return v, true
	case uint, uint16, uint64, uint32, int:
		return fmt.Sprint(v), true
	default:
		return fmt.Sprintf("*%v %v", v, reflect.TypeOf(v).Name()), false
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
