package flow

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

type TLSDetails struct {
	Client *TLSInfo `json:"client,omitempty"`
	Server *TLSInfo `json:"server,omitempty"`
}

type TLSInfo struct {
	Version       string           `json:"version,omitempty"`
	CipherSuite   string           `json:"cipherSuite,omitempty"`
	ALPN          string           `json:"alpn,omitempty"`
	ServerName    string           `json:"serverName,omitempty"`
	Offered       []string         `json:"offered,omitempty"`
	Resumed       bool             `json:"resumed,omitempty"`
	Certificates  []TLSCertificate `json:"certificates,omitempty"`
	Error         string           `json:"error,omitempty"`
	PinningLikely bool             `json:"pinningLikely,omitempty"`
}

type TLSCertificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dnsNames,omitempty"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Serial    string    `json:"serial,omitempty"`
	SHA256    string    `json:"sha256"`
}

func TLSInfoOf(cs *tls.ConnectionState) *TLSInfo {
	if cs == nil {
		return nil
	}
	out := &TLSInfo{
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ALPN:        cs.NegotiatedProtocol,
		ServerName:  cs.ServerName,
		Resumed:     cs.DidResume,
	}
	for _, c := range cs.PeerCertificates {
		out.Certificates = append(out.Certificates, CertificateOf(c))
	}
	return out
}

func CertificateOf(c *x509.Certificate) TLSCertificate {
	sum := sha256.Sum256(c.Raw)
	return TLSCertificate{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), DNSNames: c.DNSNames,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, Serial: strings.ToUpper(c.SerialNumber.Text(16)),
		SHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
	}
}
