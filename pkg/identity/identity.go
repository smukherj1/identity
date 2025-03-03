package identity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	version = "0.1"
)

type Identity struct {
	Principal string `json:"p,omitempty"`
	IssuedAt  string `json:"i,omitempty"`
	ExpiryAt  string `json:"e,omitempty"`
	Version   string `json:"v,omitempty"`
}

type credential struct {
	// Payload is the base64 encoded JSON object for Identity.
	Payload []byte `json:"p"`
	// Signature is the base64 encoded signature for the payload.
	Signature []byte `json:"s"`
}

type Manager struct {
	principal  string
	priv       *ecdsa.PrivateKey
	pub        *ecdsa.PublicKey
	pubEncoded string
}

func (m *Manager) MintToken() (string, error) {
	now := time.Now()
	expiry := now.Add(10 * time.Minute)
	i := &Identity{
		Principal: m.principal,
		IssuedAt:  fmt.Sprintf("%v", now.Unix()),
		ExpiryAt:  fmt.Sprintf("%v", expiry.Unix()),
		Version:   version,
	}
	iblob, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("unable to convert identity object into JSON: %w", err)
	}

	hashed := sha256.Sum256(iblob)
	sig, err := ecdsa.SignASN1(rand.Reader, m.priv, hashed[:])
	if err != nil {
		return "", fmt.Errorf("error signing identity object: %w", err)
	}
	c := &credential{Payload: iblob, Signature: sig}
	cblob, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("unable to convert credential object into JSON: %w", err)
	}
	token := base64.StdEncoding.EncodeToString(cblob)
	return token, nil
}

func (m *Manager) VerifyToken(token string) (*Identity, error) {
	cblob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("given token is not a valid base64 encoded string: %w", err)
	}
	c := &credential{}
	if err := json.Unmarshal(cblob, c); err != nil {
		return nil, fmt.Errorf("token did not contain a valid JSON credential object: %w", err)
	}
	ihash := sha256.Sum256(c.Payload)
	if !ecdsa.VerifyASN1(m.pub, ihash[:], c.Signature) {
		return nil, fmt.Errorf("credential failed signature verification")
	}
	i := &Identity{}
	if err := json.Unmarshal(c.Payload, i); err != nil {
		return nil, fmt.Errorf("credential payload did not contain a valid JSON identity object: %w", err)
	}
	exp, err := strconv.ParseInt(i.ExpiryAt, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("identity object had an invalid expiry time '%v', wanted 64-bit base 10 integer: %w", i.ExpiryAt, err)
	}
	et := time.Unix(exp, 0)
	if time.Now().After(et) {
		return nil, fmt.Errorf("credentials expired")
	}
	return i, nil
}

func NewManager(principal string, privPath, pubPath string) (*Manager, error) {
	priv, err := readPrivKey(privPath)
	if err != nil {
		return nil, err
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return nil, err
	}
	pubEncoded, err := encodePub(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to encode public key loaded from '%v' back into a base64 encoded string: %w", pubPath, err)
	}
	m := &Manager{
		principal:  principal,
		priv:       priv,
		pub:        pub,
		pubEncoded: pubEncoded,
	}
	return m, nil
}

func encodePub(pub *ecdsa.PublicKey) (string, error) {
	blob, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("unable to encode public key into bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

func decodePub(encodedPub string) (*ecdsa.PublicKey, error) {
	blob, err := base64.StdEncoding.DecodeString(encodedPub)
	if err != nil {
		return nil, fmt.Errorf("public key was not a valid base 64 encoded string: %w", err)
	}
	k, err := x509.ParsePKIXPublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("did not find a valid public key in the given base 64 encoded string: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("did not find a valid ECDSA P256 public key in the given base 64 encoded string")
	}
	return pub, nil
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
