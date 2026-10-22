package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestRootAndLeaves(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.CommonName() == "" || len(m.Fingerprint()) != 95 {
		t.Fatalf("root %q fingerprint %q", m.CommonName(), m.Fingerprint())
	}
	if time.Until(m.NotAfter()) < 9*365*24*time.Hour {
		t.Fatal("root expires too soon")
	}
	for _, host := range []string{"example.com", "127.0.0.1", "::1"} {
		c, err := m.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: m.Pool()}); err != nil {
			t.Fatalf("%s does not verify: %v", host, err)
		}
		again, _ := m.Leaf(host)
		if again != c {
			t.Fatal("leaf not cached")
		}
	}

	m2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Fingerprint() != m.Fingerprint() {
		t.Fatal("root regenerated on reload")
	}

	old := m.Fingerprint()
	oldLeaf, _ := m.Leaf("example.com")
	if err := m.Regenerate(); err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() == old {
		t.Fatal("regenerate kept the root")
	}
	newLeaf, _ := m.Leaf("example.com")
	if newLeaf == oldLeaf {
		t.Fatal("leaves of the old root kept")
	}
	if _, err := newLeaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: m.Pool()}); err != nil {
		t.Fatal(err)
	}
}

func TestExport(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	pemPath := filepath.Join(out, "ca.pem")
	derPath := filepath.Join(out, "ca.der")
	keyPath := filepath.Join(out, "ca.key")
	for format, path := range map[string]string{FormatPEM: pemPath, FormatDER: derPath, FormatKey: keyPath} {
		if err := m.Export(format, path, ""); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
	}
	pemBytes, _ := os.ReadFile(pemPath)
	block, _ := pem.Decode(pemBytes)
	der, _ := os.ReadFile(derPath)
	if block == nil || string(block.Bytes) != string(der) {
		t.Fatal("PEM and DER differ")
	}
	if fi, _ := os.Stat(keyPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	if err := m.Export("zip", filepath.Join(out, "x"), ""); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func newCA(t *testing.T, isCA bool) (certPEM, keyPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Corp Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), cert, key
}

func TestImportRootAndLeafValidity(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, ca, caKey := newCA(t, true)
	if _, otherKey, _, _ := newCA(t, true); m.ImportRoot(certPEM, otherKey) == nil {
		t.Error("a key not the certificate's")
	}
	if notCA, k, _, _ := newCA(t, false); m.ImportRoot(notCA, k) == nil {
		t.Error("a certificate that is not a CA")
	}
	if err := m.ImportRoot(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	leaf, err := m.Leaf("api.dev")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.dev"}); err != nil {
		t.Errorf("the leaf is not the imported root's: %v", err)
	}
	if leaf.Leaf.NotAfter.After(ca.NotAfter) {
		t.Errorf("leaf until %v, root until %v", leaf.Leaf.NotAfter, ca.NotAfter)
	}
	m2, err := New(dir)
	if err != nil || m2.CommonName() != "Corp Root" {
		t.Fatalf("reloaded %v %q", err, m2.CommonName())
	}
	m2.SetLeafValidity(30 * 24 * time.Hour)
	short, _ := m2.Leaf("api.dev")
	if d := time.Until(short.Leaf.NotAfter); d > 31*24*time.Hour || d < 29*24*time.Hour {
		t.Errorf("a 30-day leaf lasts %v", d)
	}

	p12, err := pkcs12.Modern.Encode(caKey, ca, nil, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	m3, _ := New(t.TempDir())
	if err := m3.ImportRootP12(p12, "wrong"); err == nil {
		t.Error("a wrong password")
	}
	if err := m3.ImportRootP12(p12, "s3cret"); err != nil || m3.CommonName() != "Corp Root" {
		t.Errorf("P12: %v %q", err, m3.CommonName())
	}
	path := filepath.Join(t.TempDir(), "server.p12")
	os.WriteFile(path, p12, 0o600)
	c, err := LoadP12(path, "s3cret")
	if err != nil || c.Leaf.Subject.CommonName != "Corp Root" {
		t.Errorf("LoadP12 %v", err)
	}
	if _, err := LoadP12(path, "nope"); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("LoadP12 with a wrong password: %v", err)
	}
}
