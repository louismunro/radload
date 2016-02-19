package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"text/template"
)

var macs = make([]string, 0)

func main() {

	workersPtr := flag.Int("w", 1, "number of workers to run concurrently")
	csvPtr := flag.String("f", "radload.csv", "path to csv file from which username and password will be read")
	dirPtr := flag.String("d", "/tmp/.radload", "path to directory where to store the temporary configuration files")
	macsPtr := flag.Int("m", 0, "generate a list of 'm' random MAC addresses and use them as Calling-Station-Id values")
	flag.Parse()

	if *macsPtr > 0 {
		for i := 0; i < *macsPtr; i++ {
			macs = append(macs, genMAC())
		}
		_ = "breakpoint"
	}

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

	// create the directory
	err = os.MkdirAll(*dirPtr, 0700)
	check(err)
	err = os.Chdir(*dirPtr)
	check(err)

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
	tmpl, err := template.New("eapconfig").Parse(tmpStr)
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
		go authenticate(sem, macs, flag.Args())
	}
}

func authenticate(sem chan int, macs []string, Args []string) {
	cmd := "eapol_test"

	if len(macs) > 0 {
		i := rand.Intn(len(macs) - 1)
		mac := macs[i]
		Args := append(Args, CallingStationID(mac))
	}

	if err := exec.Command(cmd, Args...).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Println("Authentication failed")
	} else {
		fmt.Println("Authentication successful")
	}

	<-sem // clear the semaphore
}

// generate a fake MAC address
func genMAC() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	// Set the local bit
	buf[0] |= 2
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func CallingStationID(mac string) string {
	// Calling-Station-Id is attribute 31, and sent as a string ("s")
	return "-N31:s:" + mac
}
