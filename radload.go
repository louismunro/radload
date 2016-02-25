package main

import (
	crypto "crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"text/template"
	"time"
)

var macs []string
var users []string
var logfile *os.File
var lock = make(chan int, 1)

type User struct {
	Identity string
	Password string
}

type Stats struct {
	requests   uint64
	success    uint64
	failures   uint64
	timeouts   uint64
	longuest   time.Duration
	shortest   time.Duration
	avg        time.Duration
	median     time.Duration
	start_time time.Time
	times      []time.Duration
}

var stats Stats

func main() {

	stats.start_time = time.Now()
	// signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		_ = <-sigs
		printStats()
		os.Exit(0)
	}()

	workersPtr := flag.Int("w", 1, "number of workers to run concurrently")
	csvPtr := flag.String("f", "radload.csv", "path to csv file from which username and password will be read")
	dirPtr := flag.String("d", "/tmp/.radload", "path to directory where to store the temporary configuration files")
	logPtr := flag.String("l", "radload.log", "path to log file")
	macsPtr := flag.Int("m", 0, "generate a list of 'm' random MAC addresses and use them as Calling-Station-Id values")
	flag.Parse()

	var err error
	logfile, err = os.Create(*logPtr)

	if *macsPtr > 0 {
		for i := 0; i < *macsPtr; i++ {
			macs = append(macs, genMAC())
		}
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
	file.Close()

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

	for _, record := range records {
		username, pass := record[0], record[1]
		users = append(users, username)
		nextUser := User{username, pass}

		f, err := os.Create(username)
		err = tmpl.Execute(f, nextUser)
		if err != nil {
			panic(err)
		}
		f.Close()
	}

	// add a call to make sure eapol_test is installed.
	var sem = make(chan int, *workersPtr)
	for {
		sem <- 1 // add to the semaphore, will block if > than workersPtr
		go authenticate(sem, macs, flag.Args())
	}
}

func authenticate(sem chan int, macs []string, Args []string) {
	user := users[mrand.Intn(len(users))] // pick a random user
	Args = append(Args, "-c"+user)

	var mac string
	if len(macs) > 0 {
		i := mrand.Intn(len(macs))

		mac = macs[i]
		Args = append(Args, CallingStationID(mac))
	}
	_ = "breakpoint"

	cmd := "eapol_test"
	before := time.Now()
	cmdErr := exec.Command(cmd, Args...).Run()
	after := time.Now()
	diff := after.Sub(before)

	var status string
	if cmdErr != nil {
		//	fmt.Fprintln(os.Stderr, cmdErr)
		status = "failed"
	} else {
		status = "successful"
	}

	lock <- 1 //  lock the shared data structures
	stats.requests++
	if diff > stats.longuest {
		stats.longuest = diff
	}
	if (stats.shortest == 0) || (stats.shortest > diff) {
		stats.shortest = diff
	}
	if status != "successful" {
		stats.failures++
	} else {
		stats.success++
	}
	stats.times = append(stats.times, diff)

	result := fmt.Sprintf("[%v / %v] %v authentication. Duration %v s\n", user, mac, status, diff.Seconds())
	io.WriteString(logfile, result)
	<-lock //  unlock the shared data

	<-sem // clear the semaphore
}

// generate a fake MAC address
func genMAC() string {
	buf := make([]byte, 6)
	_, err := crypto.Read(buf)
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

func printStats() {
	fmt.Printf("Run finished\n")
	fmt.Printf("============= Statistics =======================\n")
	fmt.Printf("")
	fmt.Printf("Total running time: %v \n", time.Now().Sub(stats.start_time))
	fmt.Printf("Total requests handled: %v \n", stats.requests)
	fmt.Printf("Successful authentications : %v \n", stats.success)
	fmt.Printf("Failed authentications : %v \n", stats.failures)
	fmt.Printf("Longuest authentication: %v \n", stats.longuest)
	fmt.Printf("Shortest authentication: %v \n", stats.shortest)
}
