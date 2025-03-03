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
	m, err := identity.NewManager(*id, *privKeyPath, *pubKeyPath)
	if err != nil {
		log.Fatalf("Error initializing credentials generator: %v", err)
	}

	t, err := m.MintToken()
	if err != nil {
		log.Fatalf("Error minting token: %v", err)
	}
	log.Printf("Token (length=%v): %v", len(t), t)
	i, err := m.VerifyToken(t)
	if err != nil {
		log.Fatalf("Token failed to verify: %v", err)
	}
	log.Printf("Verified identity token for principal %v, issued at %v, expiry %v, version %v.", i.Principal, i.IssuedAt, i.ExpiryAt, i.Version)
}
