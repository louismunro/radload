package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	fmt.Print(records)
	//	_ = "breakpoint"

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
