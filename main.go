package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
	"go-certs/internal/cert"
)

var (
	version    = "dev"
	commit     = "none"
	date       = "unknown"
	keyType    string
	keySize    int
	days       int
	outCert    string
	outKey     string
	commonName string
	sanDNS     []string
	sanIP      []string
	certFiles  []string
	chainFiles []string
	outDir     string
	host       string
	port       int
	certFile   string
	keyFile    string
	certDir    string
)

var rootCmd = &cobra.Command{
	Use:   "go-certs",
	Short: "CLI for managing TLS certificates",
	Long: fmt.Sprintf(`A command-line tool for generating, validating, and managing TLS certificates.

Examples:
  # Generate a self-signed root CA
  go-certs generate root --cn "My Root CA" --out root.crt --key-out root.key

  # Generate a server certificate (self-signed)
  go-certs generate server --cn "example.com" --out server.crt --key-out server.key

  # Generate a wildcard certificate (includes root CA)
  go-certs generate server --cn example.com --wildcard --out server.crt --key-out server.key

  # Generate a server certificate signed by an existing CA
  go-certs generate server --cn "api.example.com" --ca-cert root.crt --ca-key root.key --out server.crt --key-out server.key

  # Validate a certificate chain
  go-certs validate chain --certs server.crt --certs root.crt

  # Download certificates from a remote server
  go-certs download chain --host example.com --out-dir ./certs

  # Inspect a certificate
  go-certs inspect --cert server.crt

Version: %s
Commit: %s
Date: %s`, version, commit, date),
	Version: version,
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate TLS certificates (root CA, server, wildcard)",
	Long: `Generate TLS certificates for various use cases:
  - root: Create a self-signed root CA certificate
  - server: Create server certificates (leaf, SAN, or wildcard)

Use 'go-certs generate <subcommand> --help' for more details.`,
}

var generateRootCmd = &cobra.Command{
	Use:   "root",
	Short: "Generate a self-signed root CA certificate",
	Long: `Generate a self-signed root CA certificate that can be used to sign other certificates.

Example:
  go-certs generate root --cn "My Root CA" --out root.crt --key-out root.key`,
	RunE: runGenerateRoot,
}

var generateServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Generate a server certificate (leaf, SAN, or wildcard)",
	Long: `Generate a server certificate for TLS server authentication.

Modes:
  1. Self-signed leaf: Just specify --cn
  2. Signed by CA: Use --ca-cert and --ca-key
  3. Wildcard: Use --wildcard (generates new root CA + server cert)

Examples:
  # Self-signed server certificate
  go-certs generate server --cn "example.com" --out server.crt --key-out server.key

  # With SANs
  go-certs generate server --cn "api.example.com" --san-dns "api.example.com" --san-dns "www.example.com" --out server.crt --key-out server.key

  # Wildcard (generates new root CA automatically)
  go-certs generate server --cn example.com --wildcard --out server.crt --key-out server.key

  # Signed by existing CA
  go-certs generate server --cn "api.example.com" --ca-cert root.crt --ca-key root.key --out server.crt --key-out server.key`,
	RunE: runGenerateServer,
}

var (
	caCertFile string
	caKeyFile  string
	isWildcard bool
)

func runGenerateRoot(cmd *cobra.Command, args []string) error {
	opts := cert.CertOptions{
		CommonName: commonName,
		KeyType:    cert.KeyType(keyType),
		KeySize:    keySize,
		Days:       days,
		IsCA:       true,
	}

	certPEM, keyPEM, err := cert.GenerateRootCA(opts)
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}

	if outCert != "" {
		if err := cert.SaveCertificate(certPEM, outCert); err != nil {
			return fmt.Errorf("failed to save certificate: %w", err)
		}
		fmt.Printf("Certificate saved to %s\n", outCert)
	} else {
		fmt.Print(string(certPEM))
	}

	if outKey != "" {
		if err := cert.SavePrivateKey(keyPEM, outKey); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		fmt.Printf("Private key saved to %s\n", outKey)
	}

	return nil
}

func runGenerateServer(cmd *cobra.Command, args []string) error {
	opts := cert.CertOptions{
		CommonName:  commonName,
		KeyType:     cert.KeyType(keyType),
		KeySize:     keySize,
		Days:        days,
		SANDNSNames: sanDNS,
		SANIPs:      parseIPs(sanIP),
	}

	if isWildcard {
		if commonName == "" {
			return fmt.Errorf("domain required for wildcard certificate (--cn)")
		}
		wildcardCert, err := cert.GenerateWildcardCertificate(commonName, opts)
		if err != nil {
			return fmt.Errorf("failed to generate wildcard certificate: %w", err)
		}

		serverCertPEM := cert.CombineToPEMChain(wildcardCert.ServerCert, wildcardCert.RootCACert)

		if outCert != "" {
			if err := cert.SaveCertificate(serverCertPEM, outCert); err != nil {
				return fmt.Errorf("failed to save server certificate: %w", err)
			}
			fmt.Printf("Server certificate saved to %s\n", outCert)
		} else {
			fmt.Print(string(serverCertPEM))
		}

		if outKey != "" {
			if err := cert.SavePrivateKey(wildcardCert.ServerKey, outKey); err != nil {
				return fmt.Errorf("failed to save server key: %w", err)
			}
			fmt.Printf("Server key saved to %s\n", outKey)
		}

		rootCertOut := outCert + ".root.crt"
		rootKeyOut := outKey + ".root.key"
		if outCert != "" && outKey != "" {
			if err := cert.SaveCertificate(wildcardCert.RootCACert, rootCertOut); err != nil {
				return fmt.Errorf("failed to save root CA certificate: %w", err)
			}
			fmt.Printf("Root CA certificate saved to %s\n", rootCertOut)

			if err := cert.SavePrivateKey(wildcardCert.RootCAKey, rootKeyOut); err != nil {
				return fmt.Errorf("failed to save root CA key: %w", err)
			}
			fmt.Printf("Root CA key saved to %s\n", rootKeyOut)
		}
		return nil
	}

	if caCertFile != "" && caKeyFile != "" {
		parentCert, err := cert.LoadCertificateFromFile(caCertFile)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}
		parentKey, err := cert.LoadPrivateKeyFromFile(caKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load CA key: %w", err)
		}
		caCertPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			return fmt.Errorf("failed to read CA cert: %w", err)
		}
		certPEM, keyPEM, err := cert.GenerateLeafCertificate(opts, parentCert, parentKey)
		if err != nil {
			return fmt.Errorf("failed to generate leaf certificate: %w", err)
		}

		serverCertPEM := cert.CombineToPEMChain(certPEM, caCertPEM)

		if outCert != "" {
			if err := cert.SaveCertificate(serverCertPEM, outCert); err != nil {
				return fmt.Errorf("failed to save certificate: %w", err)
			}
			fmt.Printf("Certificate saved to %s\n", outCert)
		} else {
			fmt.Print(string(serverCertPEM))
		}

		if outKey != "" {
			if err := cert.SavePrivateKey(keyPEM, outKey); err != nil {
				return fmt.Errorf("failed to save private key: %w", err)
			}
			fmt.Printf("Private key saved to %s\n", outKey)
		}
		return nil
	}

	certPEM, keyPEM, err := cert.GenerateLeafCertificate(opts, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to generate leaf certificate: %w", err)
	}

	if outCert != "" {
		if err := cert.SaveCertificate(certPEM, outCert); err != nil {
			return fmt.Errorf("failed to save certificate: %w", err)
		}
		fmt.Printf("Certificate saved to %s\n", outCert)
	} else {
		fmt.Print(string(certPEM))
	}

	if outKey != "" {
		if err := cert.SavePrivateKey(keyPEM, outKey); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		fmt.Printf("Private key saved to %s\n", outKey)
	}

	return nil
}

func parseIPs(ipStrs []string) []net.IP {
	var ips []net.IP
	for _, ipStr := range ipStrs {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate TLS certificates and chains",
	Long: `Validate certificate chains and verify remote server certificates.

Subcommands:
  chain: Validate a local certificate chain file
  remote: Validate certificates from a remote TLS server`,
}

var validateChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Validate a local certificate chain",
	Long: `Validate a certificate chain from local PEM files.

The certificates should be provided in order (leaf first, then intermediate(s), then root).
Use the --certs flag for each certificate file.

Example:
  go-certs validate chain --certs server.crt --certs root.crt`,
	RunE: runValidateChain,
}

var validateRemoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Validate certificates from a remote server",
	Long: `Connect to a remote TLS server and validate its certificate chain.

Example:
  go-certs validate remote --host example.com --port 443`,
	RunE: runValidateRemote,
}

func runValidateChain(cmd *cobra.Command, args []string) error {
	if len(certFiles) == 0 {
		return fmt.Errorf("no certificates provided. Use --certs flag")
	}

	certs, err := cert.LoadCertificateChainFromFiles(certFiles)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	err = cert.ValidateCertificateChain(certs)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	fmt.Println("Certificate chain is valid!")

	for i, c := range certs {
		fmt.Printf("\nCertificate %d:\n", i)
		fmt.Printf("  Subject: %s\n", c.Subject.CommonName)
		fmt.Printf("  Issuer: %s\n", c.Issuer.CommonName)
		fmt.Printf("  Valid: %s to %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
		fmt.Printf("  Is CA: %v\n", c.IsCA)
		fmt.Printf("  Serial: %s\n", c.SerialNumber.String())
		if len(c.DNSNames) > 0 {
			fmt.Printf("  DNS Names: %v\n", c.DNSNames)
		}
		if len(c.IPAddresses) > 0 {
			var ips []string
			for _, ip := range c.IPAddresses {
				ips = append(ips, ip.String())
			}
			fmt.Printf("  IP Addresses: %v\n", ips)
		}
		if len(c.EmailAddresses) > 0 {
			fmt.Printf("  Email Addresses: %v\n", c.EmailAddresses)
		}
		if len(c.URIs) > 0 {
			var uris []string
			for _, uri := range c.URIs {
				uris = append(uris, uri.String())
			}
			fmt.Printf("  URIs: %v\n", uris)
		}
	}

	return nil
}

func runValidateRemote(cmd *cobra.Command, args []string) error {
	if host == "" {
		return fmt.Errorf("host is required. Use --host flag")
	}

	if port == 0 {
		port = 443
	}

	certs, err := cert.ValidateRemoteCertificateChain(host, port)
	if err != nil {
		return fmt.Errorf("failed to get remote certificates: %w", err)
	}

	fmt.Println("Remote certificate chain retrieved successfully!")

	for i, c := range certs {
		fmt.Printf("\nCertificate %d:\n", i)
		fmt.Printf("  Subject: %s\n", c.Subject.CommonName)
		fmt.Printf("  Issuer: %s\n", c.Issuer.CommonName)
		fmt.Printf("  Valid: %s to %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
		fmt.Printf("  Is CA: %v\n", c.IsCA)
		fmt.Printf("  Serial: %s\n", c.SerialNumber.String())
		if len(c.DNSNames) > 0 {
			fmt.Printf("  DNS Names: %v\n", c.DNSNames)
		}
		if len(c.IPAddresses) > 0 {
			var ips []string
			for _, ip := range c.IPAddresses {
				ips = append(ips, ip.String())
			}
			fmt.Printf("  IP Addresses: %v\n", ips)
		}
		if len(c.EmailAddresses) > 0 {
			fmt.Printf("  Email Addresses: %v\n", c.EmailAddresses)
		}
		if len(c.URIs) > 0 {
			var uris []string
			for _, uri := range c.URIs {
				uris = append(uris, uri.String())
			}
			fmt.Printf("  URIs: %v\n", uris)
		}
	}

	return nil
}

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download certificates from remote servers",
	Long: `Download TLS certificate chains from remote servers and save as PEM files.

Example:
  go-certs download chain --host example.com --out-dir ./certs`,
}

var downloadChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Download certificate chain from remote host",
	Long: `Connect to a remote TLS server and download its certificate chain.
The certificates are saved as individual PEM files in the specified output directory.

Example:
  go-certs download chain --host example.com --out-dir ./certs`,
	RunE: runDownloadChain,
}

func runDownloadChain(cmd *cobra.Command, args []string) error {
	if host == "" {
		return fmt.Errorf("host is required. Use --host flag")
	}

	if port == 0 {
		port = 443
	}

	err := cert.DownloadCertsToFile(host, port, outDir)
	if err != nil {
		return fmt.Errorf("failed to download certificates: %w", err)
	}

	fmt.Printf("Certificate chain downloaded to %s/\n", outDir)
	return nil
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect and display certificate details",
	Long: `Display detailed information about TLS certificates including:
  - Subject and Issuer
  - Validity period
  - Key usage and extended key usage
  - SAN (Subject Alternative Names)
  - Certificate chain path

Example:
  go-certs inspect --cert server.crt`,
	RunE: runInspect,
}

var validatePairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Validate certificate and private key match",
	Long: `Validate that a certificate and private key form a valid pair.

Example:
  go-certs validate pair --cert server.crt --key server.key`,
	RunE: runValidatePair,
}

var scanFolderCmd = &cobra.Command{
	Use:   "folder",
	Short: "Scan a folder for certificates and display info",
	Long: `Scan a folder for all certificate files and display their CN and SAN names.

Example:
  go-certs validate folder --dir ./certs`,
	RunE: runScanFolder,
}

func runInspect(cmd *cobra.Command, args []string) error {
	if certFile == "" {
		return fmt.Errorf("certificate file required (use --cert flag)")
	}

	c, err := cert.LoadCertificateFromFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	fmt.Println(cert.InspectCertificate(c))
	return nil
}

func runValidatePair(cmd *cobra.Command, args []string) error {
	if certFile == "" {
		return fmt.Errorf("certificate file required (use --cert flag)")
	}
	if keyFile == "" {
		return fmt.Errorf("private key file required (use --key flag)")
	}

	c, err := cert.LoadCertFromFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	key, err := cert.LoadKeyFromFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	err = cert.ValidateKeyPair(c, key)
	if err != nil {
		return fmt.Errorf("key pair validation failed: %w", err)
	}

	fmt.Println("Certificate and private key match!")
	return nil
}

func runScanFolder(cmd *cobra.Command, args []string) error {
	if certDir == "" {
		return fmt.Errorf("directory required (use --dir flag)")
	}

	certs, err := cert.ScanFolderForCerts(certDir)
	if err != nil {
		return fmt.Errorf("failed to scan folder: %w", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in folder")
		return nil
	}

	for _, info := range certs {
		fmt.Printf("\nCN: %s\n", info.CN)
		if len(info.SANDNSNames) > 0 {
			fmt.Printf("SAN DNS: %v\n", info.SANDNSNames)
		}
		if len(info.SANIPAddrs) > 0 {
			fmt.Printf("SAN IP: %v\n", info.SANIPAddrs)
		}
		fmt.Printf("Valid: %v (Expires: %s)\n", info.Valid, info.Expires.Format("2006-01-02"))
	}

	return nil
}

func main() {
	generateCmd.AddCommand(generateRootCmd)
	generateCmd.AddCommand(generateServerCmd)

	generateRootCmd.Flags().StringVar(&commonName, "cn", "", "Common Name (required)")
	generateRootCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa, ecdsa)")
	generateRootCmd.Flags().IntVar(&keySize, "key-size", 2048, "Key size (2048, 4096 for RSA)")
	generateRootCmd.Flags().IntVar(&days, "days", 365, "Validity period in days")
	generateRootCmd.Flags().StringVar(&outCert, "out", "", "Output certificate file")
	generateRootCmd.Flags().StringVar(&outKey, "key-out", "", "Output private key file")
	generateRootCmd.MarkFlagRequired("cn")

	generateServerCmd.Flags().StringVar(&commonName, "cn", "", "Common Name (required)")
	generateServerCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa, ecdsa)")
	generateServerCmd.Flags().IntVar(&keySize, "key-size", 2048, "Key size (2048, 4096 for RSA)")
	generateServerCmd.Flags().IntVar(&days, "days", 365, "Validity period in days")
	generateServerCmd.Flags().StringVar(&outCert, "out", "", "Output certificate file")
	generateServerCmd.Flags().StringVar(&outKey, "key-out", "", "Output private key file")
	generateServerCmd.Flags().StringSliceVar(&sanDNS, "san-dns", nil, "DNS names for SAN (repeatable)")
	generateServerCmd.Flags().StringSliceVar(&sanIP, "san-ip", nil, "IP addresses for SAN (repeatable)")
	generateServerCmd.Flags().StringVar(&caCertFile, "ca-cert", "", "CA certificate file to sign with")
	generateServerCmd.Flags().StringVar(&caKeyFile, "ca-key", "", "CA key file to sign with")
	generateServerCmd.Flags().BoolVar(&isWildcard, "wildcard", false, "Generate wildcard certificate")
	generateServerCmd.MarkFlagRequired("cn")
	generateServerCmd.MarkFlagRequired("out")

	validateCmd.AddCommand(validateChainCmd)
	validateCmd.AddCommand(validateRemoteCmd)
	validateCmd.AddCommand(validatePairCmd)
	validateCmd.AddCommand(scanFolderCmd)

	validateChainCmd.Flags().StringSliceVar(&certFiles, "certs", nil, "Certificate files (repeatable, at least one required)")
	validateChainCmd.MarkFlagRequired("certs")

	validateRemoteCmd.Flags().StringVar(&host, "host", "", "Remote hostname (required)")
	validateRemoteCmd.Flags().IntVar(&port, "port", 443, "Remote port (default: 443)")
	validateRemoteCmd.MarkFlagRequired("host")

	downloadCmd.AddCommand(downloadChainCmd)

	downloadChainCmd.Flags().StringVar(&host, "host", "", "Remote hostname (required)")
	downloadChainCmd.Flags().IntVar(&port, "port", 443, "Remote port (default: 443)")
	downloadChainCmd.Flags().StringVar(&outDir, "out-dir", "./certs", "Output directory")
	downloadChainCmd.MarkFlagRequired("host")

	inspectCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file to inspect (required)")
	inspectCmd.MarkFlagRequired("cert")

	validatePairCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file (required)")
	validatePairCmd.Flags().StringVar(&keyFile, "key", "", "Private key file (required)")
	validatePairCmd.MarkFlagRequired("cert")
	validatePairCmd.MarkFlagRequired("key")

	scanFolderCmd.Flags().StringVar(&certDir, "dir", "", "Directory to scan (required)")
	scanFolderCmd.MarkFlagRequired("dir")

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(inspectCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
