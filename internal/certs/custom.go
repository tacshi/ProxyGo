package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func (m *Manager) SetLeafValidity(d time.Duration) {
	if d <= 0 {
		d = 397 * 24 * time.Hour
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leafValidity == d {
		return
	}
	m.leafValidity = d
	clear(m.leaves)
}

func (m *Manager) ImportRoot(certPEM, keyPEM []byte) error {
	cert, key, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return errors.New("this certificate is not a certificate authority: its Basic Constraints must have CA=TRUE")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("this certificate may not sign certificates (Key Usage has no Certificate Sign)")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("this certificate is not valid yet")
	}
	if now.After(cert.NotAfter) {
		return errors.New("this certificate has expired")
	}
	if !samePublicKey(cert.PublicKey, key.Public()) {
		return errors.New("the private key is not the certificate's")
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.WriteFile(m.keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(m.certPath, certPEM, 0o644); err != nil {
		return err
	}
	m.rootCert, m.rootKey, m.rootPEM = cert, key, certPEM
	clear(m.leaves)
	return nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

func (m *Manager) ImportRootP12(data []byte, password string) error {
	key, cert, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return fmt.Errorf("read the P12: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return m.ImportRoot(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func LoadP12(path, password string) (*tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, cert, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, errors.New("the P12's password is wrong")
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	out := &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	for _, c := range chain {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	if _, ok := key.(crypto.Signer); !ok {
		return nil, errors.New("the P12's key cannot sign")
	}
	return out, nil
}

func LoadPEM(certPath, keyPath string) (*tls.Certificate, error) {
	if keyPath == "" {
		keyPath = certPath
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func Covers(c *tls.Certificate, host string) bool {
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	return leaf != nil && leaf.VerifyHostname(host) == nil
}

const keychainService = "ProxyGo P12 Password"

var Keychain interface {
	Set(ref, secret string) error
	Get(ref string) (string, error)
	Delete(ref string) error
} = keychain{}

type keychain struct{}

func (keychain) Set(ref, secret string) error {
	out, err := run("security", "add-generic-password", "-U", "-s", keychainService, "-a", ref, "-w", secret)
	if err != nil {
		return fmt.Errorf("keychain: %s", strings.TrimSpace(out))
	}
	return nil
}

func (keychain) Get(ref string) (string, error) {
	out, err := run("security", "find-generic-password", "-s", keychainService, "-a", ref, "-w")
	if err != nil {
		return "", fmt.Errorf("keychain: no password for %s", ref)
	}
	return strings.TrimSuffix(out, "\n"), nil
}

func (keychain) Delete(ref string) error {
	_, _ = run("security", "delete-generic-password", "-s", keychainService, "-a", ref)
	return nil
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}
