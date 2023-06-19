package main

import (
	"log"

	"aoss-verifier/cmd"
)

func main() {
	// Remove timestamps from log
	log.SetFlags(0)

	if err := cmd.Execute(); err != nil {
		log.Fatalf("%v", err)
	}
}