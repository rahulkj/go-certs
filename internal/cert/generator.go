package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

type KeyType string

const (
	KeyTypeRSA   KeyType = "rsa"
	KeyTypeECDSA KeyType = "ecdsa"
)

type CertOptions struct {
	CommonName  string
	SANDNSNames []string
	SANIPs      []net.IP
	KeyType     KeyType
	KeySize     int
	Days        int
	IsCA        bool
	Purpose     string // "server" (default), "client", or "both"
}

func normalizedDays(days int) int {
	if days <= 0 {
		return 365
	}
	return days
}

func normalizedKeyType(kt KeyType) KeyType {
	if kt == "" {
		return KeyTypeRSA
	}
	return kt
}

func GenerateKey(keyType KeyType, keySize int) (crypto.PrivateKey, error) {
	keyType = normalizedKeyType(keyType)
	switch keyType {
	case KeyTypeRSA:
		if keySize == 0 {
			keySize = 2048
		}
		if keySize < 2048 {
			keySize = 2048
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	case KeyTypeECDSA:
		switch {
		case keySize >= 521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		case keySize >= 384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		default:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	default:
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}

// subjectKeyIdentifier derives a stable key identifier for a public key.
func subjectKeyIdentifier(pub crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		h := sha256.Sum256([]byte(fmt.Sprintf("%T", pub)))
		return h[:20]
	}
	h := sha256.Sum256(b)
	return h[:20]
}

func extendedKeyUsages(purpose string) []x509.ExtKeyUsage {
	switch purpose {
	case "client":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "both":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

func keyUsageForCert(isCA bool, key crypto.PrivateKey) x509.KeyUsage {
	if isCA {
		return x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	ku := x509.KeyUsageDigitalSignature
	if _, ok := key.(*rsa.PrivateKey); ok {
		ku |= x509.KeyUsageKeyEncipherment
	}
	return ku
}

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsIP(slice []net.IP, item net.IP) bool {
	for _, ip := range slice {
		if ip.Equal(item) {
			return true
		}
	}
	return false
}

func buildDNSNames(opts CertOptions) []string {
	dnsNames := append([]string{}, opts.SANDNSNames...)
	if opts.CommonName != "" && net.ParseIP(opts.CommonName) == nil {
		if !containsStr(dnsNames, opts.CommonName) {
			dnsNames = append(dnsNames, opts.CommonName)
		}
	}
	return dnsNames
}

func buildIPs(opts CertOptions) []net.IP {
	ips := append([]net.IP{}, opts.SANIPs...)
	if opts.CommonName != "" {
		if ip := net.ParseIP(opts.CommonName); ip != nil {
			if !containsIP(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func CreateTemplate(opts CertOptions) (*x509.Certificate, error) {
	days := normalizedDays(opts.Days)
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	if opts.IsCA {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = -1
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = extendedKeyUsages(opts.Purpose)
	}

	template.DNSNames = buildDNSNames(opts)
	template.IPAddresses = buildIPs(opts)

	return template, nil
}

func GenerateRootCA(opts CertOptions) ([]byte, []byte, error) {
	key, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	days := normalizedDays(opts.Days)
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	ski := subjectKeyIdentifier(getPublicKey(key))

	template := &x509.Certificate{
		SerialNumber:          nil,
		Subject:               pkix.Name{CommonName: opts.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		SubjectKeyId:          ski,
		AuthorityKeyId:         ski,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(key), key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

func GenerateLeafCertificate(opts CertOptions, parentCert *x509.Certificate, parentKey crypto.PrivateKey) ([]byte, []byte, error) {
	key, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	days := normalizedDays(opts.Days)
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	ski := subjectKeyIdentifier(getPublicKey(key))

	dnsNames := buildDNSNames(opts)
	ipAddrs := buildIPs(opts)

	keyUsage := keyUsageForCert(false, key)

	template := &x509.Certificate{
		SerialNumber:          nil,
		Subject:               pkix.Name{CommonName: opts.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extendedKeyUsages(opts.Purpose),
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	var parent *x509.Certificate
	var signer crypto.PrivateKey
	if parentCert != nil {
		parent = parentCert
		signer = parentKey
		if len(parent.SubjectKeyId) == 0 {
			parent.SubjectKeyId = subjectKeyIdentifier(parent.PublicKey)
		}
		template.AuthorityKeyId = parent.SubjectKeyId
	} else {
		parent = template
		signer = key
		template.AuthorityKeyId = ski
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, getPublicKey(key), signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

type WildcardCert struct {
	RootCACert []byte
	RootCAKey  []byte
	ServerCert []byte
	ServerKey  []byte
}

func GenerateWildcardCertificate(domain string, opts CertOptions) (*WildcardCert, error) {
	rootCAOpts := CertOptions{
		CommonName: domain + " Root CA",
		KeyType:    opts.KeyType,
		KeySize:    opts.KeySize,
		Days:       opts.Days,
		IsCA:       true,
	}
	if rootCAOpts.Days <= 0 {
		rootCAOpts.Days = 365
	}

	rootCertPEM, rootKeyPEM, err := GenerateRootCA(rootCAOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root CA: %w", err)
	}

	rootCert, err := ParseCertificate(rootCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root cert: %w", err)
	}

	block, _ := pem.Decode(rootKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode root key PEM")
	}
	rootKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root key: %w", err)
	}

	wildcardCN := "*." + domain
	dnsNames := []string{"*." + domain, domain}

	serverKey, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	days := normalizedDays(opts.Days)
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	ski := subjectKeyIdentifier(getPublicKey(serverKey))

	aki := authorityKeyIdentifierFromCert(rootCert)

	keyUsage := keyUsageForCert(false, serverKey)

	template := &x509.Certificate{
		SerialNumber:          nil,
		Subject:               pkix.Name{CommonName: wildcardCN},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extendedKeyUsages(opts.Purpose),
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        aki,
		SubjectKeyId:          ski,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, getPublicKey(serverKey), rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create wildcard certificate: %w", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serverKeyPEM, err := encodePrivateKey(serverKey)
	if err != nil {
		return nil, err
	}

	return &WildcardCert{
		RootCACert: rootCertPEM,
		RootCAKey:  rootKeyPEM,
		ServerCert: serverCertPEM,
		ServerKey:  serverKeyPEM,
	}, nil
}

func authorityKeyIdentifierFromCert(cert *x509.Certificate) []byte {
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId
	}
	return subjectKeyIdentifier(cert.PublicKey)
}

func GenerateSANCertificate(opts CertOptions) ([]byte, []byte, error) {
	if opts.CommonName != "" && !containsStr(opts.SANDNSNames, opts.CommonName) && net.ParseIP(opts.CommonName) == nil {
		opts.SANDNSNames = append(opts.SANDNSNames, opts.CommonName)
	}

	key, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	days := normalizedDays(opts.Days)
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	ski := subjectKeyIdentifier(getPublicKey(key))

	dnsNames := buildDNSNames(opts)
	ipAddrs := buildIPs(opts)

	keyUsage := keyUsageForCert(false, key)

	template := &x509.Certificate{
		SerialNumber:          nil,
		Subject:               pkix.Name{CommonName: opts.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extendedKeyUsages(opts.Purpose),
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(key), key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

func encodePrivateKey(key interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return keyPEM, nil
}

func SaveCertificate(certPEM []byte, certPath string) error {
	return os.WriteFile(certPath, certPEM, 0644)
}

func SavePrivateKey(keyPEM []byte, keyPath string) error {
	return os.WriteFile(keyPath, keyPEM, 0600)
}

func LoadPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	// Try PKCS#8 first.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// PKCS#1 RSA.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// SEC1 EC.
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed to parse private key from %s", path)
}

func contains(slice []string, item string) bool {
	return containsStr(slice, item)
}

func getPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func CombineToPEMChain(certs ...[]byte) []byte {
	var result []byte
	for _, cert := range certs {
		result = append(result, cert...)
	}
	return result
}
