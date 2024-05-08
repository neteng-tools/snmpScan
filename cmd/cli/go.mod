module snmpCLI

go 1.22.2

require github.com/neteng-tools/snmpScan/pkg/Scanner v0.0.0

replace github.com/neteng-tools/snmpScan/pkg/Scanner => ../../pkg/Scanner

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-ping/ping v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gosnmp/gosnmp v1.37.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
