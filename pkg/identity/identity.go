package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	version = "0.1"
)

type Identity struct {
	ID              string `json:"id,omitempty"`
	IssuedAt        uint64 `json:"i,omitempty"`
	ExpiryAt        uint64 `json:"e,omitempty"`
	Version         string `json:"v,omitempty"`
	VerificationKey string `json:"vk,omitempty"`
}

type credential struct {
	// Payload is the base64 encoded Identity.
	Payload string `json:"p"`
	// Signature is the base64 encoded signature for the payload.
	Signature string `json:"s"`
}

type Manager struct {
	id   string
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

func (m *Manager) MintToken() (string, error) {
	return "", nil
}

func ParseToken(token string) *Identity {
	return nil
}

func NewManager(id string, privPath, pubPath string) (*Manager, error) {
	priv, err := readPrivKey(privPath)
	if err != nil {
		return nil, err
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		id:   id,
		priv: priv,
		pub:  pub,
	}
	return m, nil
}

func readPem(filename string) (*pem.Block, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file '%v': %w", filename, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from file '%v'", filename)
	}
	return block, nil
}

func readPrivKey(filename string) (*ecdsa.PrivateKey, error) {
	privPem, err := readPem(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key PEM file: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return priv, nil
}

func readPublicKey(filename string) (*ecdsa.PublicKey, error) {
	pubPem, err := readPem(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key PEM file: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Type assert to ECDSA public key
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key loaded from '%v' was not a ECDSA public key", filename)
	}

	return ecdsaPub, nil
}
