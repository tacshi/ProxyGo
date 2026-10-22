package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- the keychain names certificates by their SHA-1 hash.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type Manager struct {
	dir      string
	certPath string
	keyPath  string

	mu           sync.RWMutex
	rootCert     *x509.Certificate
	rootKey      crypto.Signer
	rootPEM      []byte
	leaves       map[string]*tls.Certificate
	leafKey      *ecdsa.PrivateKey
	leafValidity time.Duration
}

func New(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{
		dir:      dir,
		certPath: filepath.Join(dir, "proxygo-ca.pem"),
		keyPath:  filepath.Join(dir, "proxygo-key.pem"),
		leaves:   map[string]*tls.Certificate{},
	}
	if err := m.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := m.generate(); err != nil {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.leafKey = key
	return m, nil
}

func (m *Manager) load() error {
	certPEM, err := os.ReadFile(m.certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(m.keyPath)
	if err != nil {
		return err
	}
	cert, key, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.rootCert, m.rootKey, m.rootPEM = cert, key, certPEM
	return nil
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("root certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("root key is not PEM")
	}
	var key any
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("root key cannot sign")
	}
	return cert, signer, nil
}

func (m *Manager) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	now := time.Now()
	hostname, _ := os.Hostname()
	hostname = strings.TrimSuffix(hostname, ".local")
	if hostname == "" {
		hostname = "Mac"
	}
	cn := fmt.Sprintf("ProxyGo CA (%s, %s, %s)", now.Format("2 Jan 2006"), hostname, strings.ToUpper(rand.Text()[:8]))
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"ProxyGo"},
			OrganizationalUnit: []string{"ProxyGo"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(m.keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(m.certPath, certPEM, 0o644); err != nil { // #nosec G306 -- the public CA certificate, which other tools read.
		return err
	}
	m.rootCert, m.rootKey, m.rootPEM = cert, key, certPEM
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n.Add(n, big.NewInt(1))
}

func (m *Manager) Regenerate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.generate(); err != nil {
		return err
	}
	clear(m.leaves)
	return nil
}

func (m *Manager) CertPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return bytes.Clone(m.rootPEM)
}

func (m *Manager) CertDER() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return bytes.Clone(m.rootCert.Raw)
}

func (m *Manager) KeyPEM() ([]byte, error) {
	return os.ReadFile(m.keyPath)
}

func (m *Manager) CertPath() string { return m.certPath }

func (m *Manager) Dir() string { return m.dir }

func (m *Manager) CommonName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootCert.Subject.CommonName
}

func (m *Manager) NotAfter() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootCert.NotAfter
}

func (m *Manager) Fingerprint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sum := sha256.Sum256(m.rootCert.Raw)
	return colonHex(sum[:])
}

func colonHex(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))
	var out strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(s[i : i+2])
	}
	return out.String()
}

func (m *Manager) Pool() *x509.CertPool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := x509.NewCertPool()
	p.AddCert(m.rootCert)
	return p
}

func (m *Manager) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, errors.New("no host for a certificate")
	}
	m.mu.RLock()
	c := m.leaves[host]
	root, rootKey, validity := m.rootCert, m.rootKey, m.leafValidity
	m.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	if validity <= 0 {
		validity = 397 * 24 * time.Hour
	}
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"ProxyGo"}},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &m.leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c = &tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: m.leafKey, Leaf: leaf}
	m.mu.Lock()
	if len(m.leaves) > 2048 {
		clear(m.leaves)
	}
	m.leaves[host] = c
	m.mu.Unlock()
	return c, nil
}

func (m *Manager) Trusted() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "security", "verify-cert", "-c", m.certPath, "-p", "ssl", "-L").Run() == nil // #nosec G204 -- security, given ProxyGo's own certificate.
}

func loginKeychain() string {
	home, _ := os.UserHomeDir()
	k := filepath.Join(home, "Library/Keychains/login.keychain-db")
	if _, err := os.Stat(k); err != nil {
		return "login.keychain"
	}
	return k
}

func (m *Manager) Install() error {
	out, err := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-p", "basic", "-k", loginKeychain(), m.certPath).CombinedOutput() // #nosec G204 -- security, given ProxyGo's own certificate.
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *Manager) Uninstall() error {
	_ = exec.Command("security", "remove-trusted-cert", m.certPath).Run() // #nosec G204 -- security, given ProxyGo's own certificate.
	m.mu.RLock()
	sum := sha1.Sum(m.rootCert.Raw) // #nosec G401 -- the keychain names certificates by their SHA-1 hash.
	m.mu.RUnlock()
	out, err := exec.Command("security", "delete-certificate", "-Z", strings.ToUpper(hex.EncodeToString(sum[:])), loginKeychain()).CombinedOutput() // #nosec G204 -- security, given ProxyGo's own certificate.
	if err != nil && !strings.Contains(string(out), "Unable to delete certificate matching") {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

const (
	FormatPEM = "pem"
	FormatDER = "der"
	FormatKey = "key"
	FormatP12 = "p12"
)

func (m *Manager) Export(format, path, password string) error {
	switch format {
	case FormatPEM:
		return os.WriteFile(path, m.CertPEM(), 0o644) // #nosec G306 -- an exported public certificate.
	case FormatDER:
		return os.WriteFile(path, m.CertDER(), 0o644) // #nosec G306 -- an exported public certificate.
	case FormatKey:
		b, err := m.KeyPEM()
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0o600)
	case FormatP12:
		m.mu.RLock()
		b, err := pkcs12.LegacyDES.Encode(m.rootKey, m.rootCert, nil, password)
		m.mu.RUnlock()
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0o600)
	}
	return fmt.Errorf("unknown format %q", format)
}
