package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"text/template"
)

func main() {

	workersPtr := flag.Int("w", 1, "number of workers to run concurrently")
	csvPtr := flag.String("f", "/tmp/radload/up.csv", "path to csv file from which username and password will be read")
	flag.Parse()

	// read usernames/passwords from csv and generate conf files
	file, err := os.Open(*csvPtr)
	if err != nil {
		os.Exit(1)
	}
	r := csv.NewReader(io.Reader(file))
	records, err := r.ReadAll()
	if err != nil {
		os.Exit(1)
	}

	tmpStr := `
network={
        ssid="EXAMPLE-SSID"
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="{{.Identity}}"
        anonymous_identity="anonymous"
        password="{{.Password}}"
        phase2="autheap=MSCHAPV2"

	#  Uncomment the following to perform server certificate validation.
#	ca_cert="/root/ca.crt"
}
`
	tmpl, err := template.New("peap").Parse(tmpStr)
	if err != nil {
		os.Exit(3)
	}

	type User struct {
		Password string
		Identity string
	}

	for _, record := range records {
		username, pass := record[0], record[1]
		nextUser := User{username, pass}

		f, err := os.Create(username)
		err = tmpl.Execute(f, nextUser)
		if err != nil {
			panic(err)
		}
	}

	_ = "breakpoint"
	os.Exit(3)

	var sem = make(chan int, *workersPtr)
	for {
		sem <- 1 // add to the semaphore, will block if > than workersPtr
		go authenticate(sem, flag.Args())
	}
}

func authenticate(sem chan int, trailingArgs []string) {
	cmd := "eapol_test"

	if err := exec.Command(cmd, trailingArgs...).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Println("Authentication failed")
	} else {
		fmt.Println("Authentication successful")
	}

	<-sem // clear the semaphore
}
