package main

import (
	"flag"
	"log"

	"github.com/smukherj1/identity/pkg/identity"
)

var (
	privKeyPath = flag.String("priv", "", "Path to ECDSA private key.")
	pubKeyPath  = flag.String("pub", "", "Path to ECDSA public key.")
	id          = flag.String("id", "", "The identity presented in generated credentials.")
)

func main() {
	flag.Parse()
	if len(*id) == 0 {
		log.Fatalf("--id is required.")
	}
	if len(*privKeyPath) == 0 {
		log.Fatalf("--priv is required.")
	}
	if len(*pubKeyPath) == 0 {
		log.Fatalf("--pub is required.")
	}
	_, err := identity.NewManager(*id, *privKeyPath, *pubKeyPath)
	if err != nil {
		log.Fatalf("Error initializing credentials generator: %v", err)
	}
}
