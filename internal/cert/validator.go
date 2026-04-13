package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertChain struct {
	Certs []*x509.Certificate
}

func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return ParseCertificate(data)
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
}

func LoadCertificateChainFromFiles(paths []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for _, path := range paths {
		cert, err := LoadCertificateFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate from %s: %w", path, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func ValidateCertificateChain(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	for i, cert := range certs {
		if time.Now().After(cert.NotAfter) {
			return fmt.Errorf("certificate %d is expired (expired on %s)", i, cert.NotAfter.Format(time.RFC3339))
		}

		if time.Now().Before(cert.NotBefore) {
			return fmt.Errorf("certificate %d is not yet valid (valid from %s)", i, cert.NotBefore.Format(time.RFC3339))
		}
	}

	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			err := certs[i].CheckSignatureFrom(certs[i+1])
			if err != nil {
				return fmt.Errorf("certificate chain validation failed at %d: %w", i, err)
			}
		}
	}

	return nil
}

func ValidateRemoteCertificateChain(host string, port int) ([]*x509.Certificate, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates received from server")
	}

	return certs, nil
}

func DownloadCertificateChain(host string, port int) (CertChain, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return CertChain{}, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertChain{}, fmt.Errorf("no certificates received from server")
	}

	return CertChain{Certs: certs}, nil
}

func SaveCertificateChain(chain CertChain, prefix string) error {
	for i, cert := range chain.Certs {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		filename := fmt.Sprintf("%s-%d.pem", prefix, i)
		if err := os.WriteFile(filename, certPEM, 0644); err != nil {
			return fmt.Errorf("failed to save certificate %d: %w", i, err)
		}
	}
	return nil
}

func InspectCertificate(cert *x509.Certificate) string {
	dnsNames, ipAddrs := parseSANFromCert(cert)
	return fmt.Sprintf(`Subject: %s
Issuer: %s
Serial Number: %s
Valid From: %s
Valid Until: %s
Key Usage: %v
Is CA: %v
DNS Names: %v
IP Addresses: %v`,
		cert.Subject.CommonName,
		cert.Issuer.CommonName,
		cert.SerialNumber.String(),
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
		cert.KeyUsage,
		cert.IsCA,
		dnsNames,
		ipAddrs,
	)
}

func parseSANFromCert(cert *x509.Certificate) ([]string, []string) {
	var dnsNames []string
	var ipAddrs []string

	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			var rawValues []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &rawValues); err != nil {
				return nil, nil
			}
			for _, rv := range rawValues {
				if rv.Tag == 2 { // DNS
					dnsNames = append(dnsNames, string(rv.Bytes))
				} else if rv.Tag == 7 { // IP
					ipAddrs = append(ipAddrs, net.IP(rv.Bytes).String())
				}
			}
		}
	}
	return dnsNames, ipAddrs
}

func GetCertDNSNames(cert *x509.Certificate) []string {
	return cert.DNSNames
}

func GetCertIPAddresses(cert *x509.Certificate) []string {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return ips
}

func IsCertificateExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

func IsCertificateValid(cert *x509.Certificate) bool {
	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

func GetCertificateExpiration(cert *x509.Certificate) time.Time {
	return cert.NotAfter
}

func ConnectAndGetCerts(host string, port int) ([]*x509.Certificate, error) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	conn.Handshake()
	certs := conn.ConnectionState().PeerCertificates

	return certs, nil
}

func DownloadCertsToFile(host string, port int, outDir string) error {
	certs, err := ConnectAndGetCerts(host, port)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", outDir, err)
	}

	for i, cert := range certs {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		filename := fmt.Sprintf("%s/cert-%d.pem", outDir, i)
		if err := os.WriteFile(filename, certPEM, 0644); err != nil {
			return fmt.Errorf("failed to save certificate %d: %w", i, err)
		}
	}

	return nil
}

func ValidateKeyPair(cert *x509.Certificate, key interface{}) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if err := k.Validate(); err != nil {
			return fmt.Errorf("RSA key validation failed: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not RSA")
		}
		if k.N.Cmp(pub.N) != 0 {
			return fmt.Errorf("certificate and private key do not match")
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not ECDSA")
		}
		if k.X.Cmp(pub.X) != 0 || k.Y.Cmp(pub.Y) != 0 {
			return fmt.Errorf("certificate and private key do not match")
		}
	default:
		return fmt.Errorf("unsupported key type")
	}
	return nil
}

type CertInfo struct {
	CN          string
	SANDNSNames []string
	SANIPAddrs  []string
	Valid       bool
	Expires     time.Time
	IsCA        bool
}

func LoadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM: %s", path)
	}

	if block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
}

func LoadKeyFromFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM: %s", path)
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func GetCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		CN:          cert.Subject.CommonName,
		SANDNSNames: cert.DNSNames,
		Valid:       IsCertificateValid(cert),
		Expires:     cert.NotAfter,
		IsCA:        cert.IsCA,
	}
	for _, ip := range cert.IPAddresses {
		info.SANIPAddrs = append(info.SANIPAddrs, ip.String())
	}
	return info
}

func ScanFolderForCerts(dir string) ([]CertInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var certs []CertInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isCertFile(name) {
			continue
		}

		cert, err := LoadCertFromFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		certs = append(certs, GetCertInfo(cert))
	}

	return certs, nil
}

func isCertFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".pem" || ext == ".crt" || ext == ".cer"
}
