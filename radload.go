package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

func main() {

	workersPtr := flag.Int("w", 1, "number of workers to run concurrently")
	//csvPtr := flag.String("f", 1, "path to csv file from which username and password will be read")
	flag.Parse()
	fmt.Println("tail:", flag.Args())

	var sem = make(chan int, *workersPtr)
	//	_ = "breakpoint"
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
