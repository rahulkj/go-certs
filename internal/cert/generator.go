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
	"encoding/asn1"
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
}

func GenerateKey(keyType KeyType, keySize int) (crypto.PrivateKey, error) {
	switch keyType {
	case KeyTypeRSA:
		if keySize == 0 {
			keySize = 2048
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	case KeyTypeECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}

func CreateTemplate(opts CertOptions) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(opts.Days) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	if opts.IsCA {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.BasicConstraintsValid = true
		template.MaxPathLen = 0
	}

	if len(opts.SANDNSNames) > 0 || len(opts.SANIPs) > 0 {
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:    []int{2, 5, 29, 17},
				Value: marshalSAN(opts.SANDNSNames, opts.SANIPs),
			},
		}
	}

	return template, nil
}

func marshalSAN(dnsNames []string, ips []net.IP) []byte {
	var rawValues []asn1.RawValue

	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   2, // DNS
			Bytes: []byte(name),
		})
	}
	for _, ip := range ips {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   7, // IP
			Bytes: ip,
		})
	}

	bs, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil
	}
	return bs
}

func GenerateRootCA(opts CertOptions) ([]byte, []byte, error) {
	key, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
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

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              opts.SANDNSNames,
	}

	if len(opts.SANDNSNames) > 0 || len(opts.SANIPs) > 0 {
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:    []int{2, 5, 29, 17},
				Value: marshalSAN(opts.SANDNSNames, opts.SANIPs),
			},
		}
	}

	var parent *x509.Certificate
	var signer crypto.PrivateKey
	if parentCert != nil {
		parent = parentCert
		signer = parentKey
		template.AuthorityKeyId = parentCert.SubjectKeyId
	} else {
		parent = template
		signer = key
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

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	aki := authorityKeyIdentifierFromCert(rootCert)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: wildcardCN,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        aki,
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
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}

func GenerateSANCertificate(opts CertOptions) ([]byte, []byte, error) {
	if opts.CommonName != "" && !contains(opts.SANDNSNames, opts.CommonName) {
		opts.SANDNSNames = append(opts.SANDNSNames, opts.CommonName)
	}

	key, err := GenerateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if len(opts.SANDNSNames) > 0 || len(opts.SANIPs) > 0 {
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:    []int{2, 5, 29, 17},
				Value: marshalSAN(opts.SANDNSNames, opts.SANIPs),
			},
		}
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
	var keyBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA key: %w", err)
		}
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
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
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
