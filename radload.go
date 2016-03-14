package main

import (
	crypto "crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/montanaflynn/stats"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"text/template"
	"time"
)

type (
	user struct {
		Identity string
		Password string
	}

	confTmp struct {
		peap string
		tls  string
	}

	rl_stats struct {
		requests   uint64
		success    uint64
		failures   uint64
		timeouts   uint64
		start_time time.Time
		times      []float64
	}

	rl_config struct {
		workers uint64
		csv     string
		dir     string
		log     string
		MACs    uint64
		maxreq  uint64
		maxtime uint64
		clean   bool
		conf    string
	}
)

var (
	macs     []string
	logfile  *os.File
	lock     = make(chan int, 1)
	reqstats rl_stats
	users    []string
	Config   rl_config
	cliArgs  []string
	usersmac = make(map[string]string)
)

const (
	cmd        string = "eapol_test"
	confSuffix        = ".rl_conf" // appended to all configfiles created
)

func main() {

	reqstats.start_time = time.Now()
	// signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		_ = <-sigs
		atExit(0)
	}()

	setConfig()
	/*

	  EAPOL_TEST flags
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
	if Config.maxtime > 0 {
		go func() {
			time.Sleep(time.Duration(Config.maxtime) * time.Second)
			fmt.Fprintf(os.Stderr, "Time's up. Exiting.\n")
			atExit(0)
		}()
	}

	logfile, err = os.Create(Config.log)

	if Config.MACs > 0 {
		for i := uint64(0); i < Config.MACs; i++ {
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
	file, err := os.Open(Config.csv)
	check(err)
	r := csv.NewReader(io.Reader(file))
	records, err := r.ReadAll()
	check(err)
	file.Close()

	// create the directory
	err = os.MkdirAll(Config.dir, 0700)
	check(err)
	err = os.Chdir(Config.dir)
	check(err)

	tmpl, err := template.New("eapconfig").Parse(confTemplate.peap)
	if err != nil {
		check(err)
	}

	for _, record := range records {
		username, pass := record[0], record[1]
		usersmac[username] = record[2]
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

	var sem = make(chan int, Config.workers)
	for {
		sem <- 1 // add to the semaphore, will block if > than workersPtr

		if (Config.maxreq != 0) && (reqstats.requests >= Config.maxreq) {
			fmt.Fprintf(os.Stderr, "Maximum requests reached. Exiting.\n")
			printStats()
			os.Exit(0)
		}
		go authenticate(sem)
	}
}

func authenticate(sem chan int) {
	user := users[mrand.Intn(len(users))] // pick a random user
	cliArgs = append(cliArgs, "-c"+user+".rl_conf")

	mac := usersmac[user]
	if mac == "" {
		i := mrand.Intn(len(macs))
		mac = macs[i]
	}
	cliArgs = append(cliArgs, fmt.Sprintf("-M%v", mac))

	_ = "breakpoint"
	before := time.Now()
	cmdErr := exec.Command(cmd, cliArgs...).Run()
	diff := time.Since(before).Seconds()

	var status string
	var failed bool
	if cmdErr != nil {
		//	fmt.Fprintln(os.Stderr, cmdErr)
		status = "failed"
		failed = true
	} else {
		failed = false
		status = "successful"
	}

	lock <- 1 //  lock the shared data structures
	reqstats.requests++
	if failed {
		reqstats.failures++
	} else {
		reqstats.success++
	}
	reqstats.times = append(reqstats.times, diff)

	result := fmt.Sprintf("[%v / %v] %v authentication. Duration %v s\n", user, mac, status, diff)
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

	max, _ := stats.Max(reqstats.times)
	min, _ := stats.Min(reqstats.times)
	median, _ := stats.Median(reqstats.times)
	_ = "breakpoint"

	fmt.Printf("============= Statistics =======================\n")
	fmt.Printf("\n")
	fmt.Printf("Total running time: %v \n", time.Now().Sub(reqstats.start_time))
	fmt.Printf("Total requests handled: %v \n", reqstats.requests)
	fmt.Printf("Successful authentications : %v \n", reqstats.success)
	fmt.Printf("Failed authentications : %v \n", reqstats.failures)
	fmt.Printf("Longuest authentication: %v s\n", max)
	fmt.Printf("Shortest authentication: %v s\n", min)
	fmt.Printf("Median authentication time: %v s\n", median)
}

func cleanUp() {
	if Config.clean {
		for _, user := range users {
			os.Remove(Config.dir + "/" + user + confSuffix)
		}
	}
}

func setConfig() {

	confPtr := flag.String("f", "~/.radload.conf", "path to configuration file")
	workersPtr := flag.Int("w", 1, "number of workers to run concurrently (defaults to 1)")
	csvPtr := flag.String("x", "radload.csv", "path to csv file from which username and password will be read")
	dirPtr := flag.String("d", "/tmp/.radload", "path to directory where to store the temporary configuration files")
	logPtr := flag.String("l", "radload.log", "path to log file")
	macsPtr := flag.Int("m", 10000, "generate a list of 'm' random MAC addresses and use them as Calling-Station-Id values (defaults to 10000)")
	countPtr := flag.Uint64("r", 0, "run a maximum of 'r' requests before exiting (defaults to infinity)")
	timePtr := flag.Int("t", 0, "run for a maximum of 't' seconds before exiting (defaults to infinity)")
	cleanPtr := flag.Bool("c", false, "Cleanup. Deletes all configuration files at exit.")
	flag.Parse()
	cliArgs = flag.Args()

	if *confPtr == "~/.radload.conf" {
		Config.conf = os.Getenv("HOME") + "/.radload.conf"
	} else {
		Config.conf = *confPtr
	}

	Config.workers = uint64(*workersPtr)
	Config.csv = *csvPtr
	Config.dir = *dirPtr
	Config.log = *logPtr
	Config.MACs = uint64(*macsPtr)
	Config.maxreq = *countPtr
	Config.maxtime = uint64(*timePtr)
	Config.clean = *cleanPtr

}
