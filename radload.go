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

type user struct {
	Identity string
	Password string
}

type confTmp struct {
	peap string
	tls  string
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
var cleanPtr *bool
var dirPtr *string

const cmd string = "eapol_test"
const confSuffix = ".rl_conf" // appended to all configfiles created

func main() {

	stats.start_time = time.Now()
	// signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		_ = <-sigs
		atExit(0)
	}()

	workersPtr := flag.Int("w", 1, "number of workers to run concurrently (defaults to 1)")
	csvPtr := flag.String("f", "radload.csv", "path to csv file from which username and password will be read")
	dirPtr = flag.String("d", "/tmp/.radload", "path to directory where to store the temporary configuration files")
	logPtr := flag.String("l", "radload.log", "path to log file")
	macsPtr := flag.Int("m", 0, "generate a list of 'm' random MAC addresses and use them as Calling-Station-Id values")
	countPtr := flag.Uint64("r", 0, "run a maximum of 'r' requests before exiting (defaults to infinity)")
	timePtr := flag.Int("t", 0, "run for a maximum of 't' seconds before exiting (defaults to infinity)")
	cleanPtr = flag.Bool("c", false, "Cleanup. Deletes all configuration files at exit.")
	flag.Parse()

	/*
	  -c<conf> = configuration file
	  -a<AS IP> = IP address of the authentication server, default 127.0.0.1
	  -p<AS port> = UDP port of the authentication server, default 1812
	  -s<AS secret> = shared secret with the authentication server, default 'radius'
	  -A<client IP> = IP address of the client, default: select automatically
	  -r<count> = number of re-authentications
	  -W = wait for a control interface monitor before starting
	  -S = save configuration after authentication
	  -n = no MPPE keys expected
	  -t<timeout> = sets timeout in seconds (default: 30 s)
	  -C<Connect-Info> = RADIUS Connect-Info (default: CONNECT 11Mbps 802.11b)
	  -M<client MAC address> = Set own MAC address (Calling-Station-Id,
	                           default: 02:00:00:00:00:01)
	  -o<server cert file> = Write received server certificate
	                         chain to the specified file
	*/

	// exit early if the command is not found
	_, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v not found in PATH or not executable. Exiting.\n", cmd)
		os.Exit(2)
	}

	// take care of maximum running time
	if *timePtr > 0 {
		go func() {
			time.Sleep(time.Duration(*timePtr) * time.Second)
			fmt.Fprintf(os.Stderr, "Time's up. Exiting.\n")
			atExit(0)
		}()
	}

	logfile, err = os.Create(*logPtr)

	if *macsPtr > 0 {
		for i := 0; i < *macsPtr; i++ {
			macs = append(macs, genMAC())
		}
	}

	confTemplate := confTmp{
		peap: `
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
		}`,
		tls: `
		  network={
			  ssid="YOUR-SSID"
			  scan_ssid=1
			  key_mgmt=WPA-EAP
			  pairwise=CCMP TKIP
			  group=CCMP TKIP
			  eap=TLS
			  identity="{{.Identity}}"
			  ca_cert="/etc/certs/cacert.pem"
			  client_cert="/etc/certs/cert.pem"
			  private_key="/etc/certs/key.pem"
			  private_key_passwd="{{.Password}}"
   		}`,
	}

	// read usernames/passwords from csv and generate conf files
	file, err := os.Open(*csvPtr)
	check(err)
	r := csv.NewReader(io.Reader(file))
	records, err := r.ReadAll()
	check(err)
	file.Close()

	// create the directory
	err = os.MkdirAll(*dirPtr, 0700)
	check(err)
	err = os.Chdir(*dirPtr)
	check(err)

	tmpl, err := template.New("eapconfig").Parse(confTemplate.peap)
	if err != nil {
		check(err)
	}

	for _, record := range records {
		username, pass := record[0], record[1]
		users = append(users, username)
		nextUser := user{username, pass}

		f, err := os.Create(username + confSuffix)
		check(err)
		err = tmpl.Execute(f, nextUser)
		if err != nil {
			panic(err)
		}
		f.Close()
	}

	var sem = make(chan int, *workersPtr)
	for {
		sem <- 1 // add to the semaphore, will block if > than workersPtr

		if (*countPtr != 0) && (stats.requests >= *countPtr) {
			fmt.Fprintf(os.Stderr, "Maximum requests reached. Exiting.\n")
			printStats()
			os.Exit(0)
		}
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
		Args = append(Args, fmt.Sprintf("-M%v", mac))
	}
	_ = "breakpoint"

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
		fmt.Fprintf(os.Stderr, "%v", e)
		os.Exit(1)
	}
}

func atExit(status int) {
	printStats()
	cleanUp()
	os.Exit(status)
}

func printStats() {
	fmt.Printf("Run finished\n")
	fmt.Printf("============= Statistics =======================\n")
	fmt.Printf("\n")
	fmt.Printf("Total running time: %v \n", time.Now().Sub(stats.start_time))
	fmt.Printf("Total requests handled: %v \n", stats.requests)
	fmt.Printf("Successful authentications : %v \n", stats.success)
	fmt.Printf("Failed authentications : %v \n", stats.failures)
	fmt.Printf("Longuest authentication: %v \n", stats.longuest)
	fmt.Printf("Shortest authentication: %v \n", stats.shortest)
}

func cleanUp() {
	if *cleanPtr {
		for _, user := range users {
			os.Remove(*dirPtr + "/" + user + confSuffix)
		}
	}
}
