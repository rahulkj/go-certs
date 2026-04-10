# Go CLI for Certificate Management

## Project Overview

Create a command-line tool written in Go for managing TLS certificates. The tool should support generating various types of certificates, validating certificate chains, and downloading certificate chains from remote servers.

## Functional Requirements

### 1. Certificate Generation

#### 1.1 Self-Signed Certificates
- Generate self-signed certificates using Go's `crypto/tls` package
- Support RSA (2048, 4096) and ECDSA (P-256, P-384) key algorithms
- Configurable validity period (default: 365 days)
- Output to PEM format

#### 1.2 Wildcard Certificates
- Generate certificates with wildcard Common Name (e.g., `*.example.com`)
- Support specifying the domain base (e.g., `example.com` produces `*.example.com`)
- Same key algorithm options as self-signed certificates

#### 1.3 SAN (Subject Alternative Name) Certificates
- Support multiple DNS names in SAN extension
- Support IP addresses in SAN extension
- Configurable via command-line flags (repeatable flag for multiple values)

### 2. Certificate Validation

#### 2.1 Download Certificate Chain from Remote
- Connect to remote host using TLS and retrieve certificate chain
- Support custom port (default: 443)
- Support hostname verification
- Output downloaded certificates to local files

#### 2.2 Validate Local Certificate Chain
- Accept certificate files from local filesystem
- Support PEM (.pem, .crt) and DER (.der, .cer) formats
- Validate certificate chain integrity
- Check certificate expiration dates
- Verify certificate signature (if intermediate certs provided)
- Display certificate details (subject, issuer, validity, SANs)

### 3. Output Formats

- PEM format (.pem, .crt)
- DER format (.der, .cer)
- Private key output (PEM encoded)
- Certificate chain output

## Command Structure

```bash
go-certs [command] [flags]
```

### Commands

1. **generate** - Generate new certificates
   - `generate root` - Generate self-signed root CA
   - `generate leaf` - Generate leaf certificate signed by root CA
   - `generate wildcard` - Generate wildcard certificate
   - `generate san` - Generate SAN certificate

2. **validate** - Validate certificates
   - `validate chain` - Validate certificate chain from files
   - `validate remote` - Download and validate chain from remote

3. **download** - Download certificates
   - `download chain` - Download certificate chain from remote host

4. **inspect** - Display certificate information
   - `inspect cert` - Show certificate details

### Flags

Common flags across commands:
- `--key-size` - RSA key size (2048, 4096)
- `--key-type` - Key type (rsa, ecdsa)
- `--days` - Validity period in days
- `--out` - Output file path
- `--key-out` - Private key output file path

Generate command flags:
- `--cn` - Common Name
- `--san-dns` - DNS names for SAN (repeatable)
- `--san-ip` - IP addresses for SAN (repeatable)
- `--root-ca` - Path to root CA for signing
- `--root-key` - Path to root CA private key

Validate command flags:
- `--certs` - Certificate files (repeatable, at least one required)
- `--chain` - Full chain files (optional)

Download command flags:
- `--host` - Remote hostname (required)
- `--port` - Remote port (default: 443)
- `--out-dir` - Output directory for certificates

## Technical Implementation

### Dependencies

- Go standard library (`crypto/tls`, `crypto/x509`, `crypto/rand`, `encoding/pem`)
- No external dependencies required

### File Structure

```
go-certs/
├── cmd/
│   ├── root.go
│   ├── generate.go
│   ├── validate.go
│   ├── download.go
│   └── inspect.go
├── internal/
│   ├── cert/
│   │   ├── generator.go
│   │   ├── validator.go
│   │   └── downloader.go
│   └── utils/
│       ├── file.go
│       └── format.go
├── go.mod
└── main.go
```

### Key Functions

1. **GenerateCertificate** - Creates new certificate with specified options
2. **GenerateWildcardCertificate** - Creates wildcard certificate
3. **GenerateSANCertificate** - Creates certificate with SAN extensions
4. **ValidateCertificateChain** - Validates certificate chain from files
5. **DownloadCertificateChain** - Downloads and saves certificate chain
6. **InspectCertificate** - Displays certificate details

## Usage Examples

### Generate self-signed certificate
```bash
go-certs generate leaf --cn "example.com" --out server.crt --key-out server.key
```

### Generate wildcard certificate
```bash
go-certs generate wildcard --cn "*.example.com" --out wildcard.crt --key-out wildcard.key
```

### Generate SAN certificate
```bash
go-certs generate san --cn "example.com" --san-dns "example.com" --san-dns "www.example.com" --san-ip "1.2.3.4" --out san.crt --key-out san.key
```

### Download certificate chain from remote
```bash
go-certs download chain --host "example.com" --out-dir ./certs
```

### Validate local certificate chain
```bash
go-certs validate chain --certs server.crt --certs ca.crt
```

### Inspect certificate
```bash
go-certs inspect cert server.crt
```

## Acceptance Criteria

1. ✓ CLI runs without errors for all commands
2. ✓ Generated certificates are valid and can be used for TLS
3. ✓ Wildcard certificates correctly generate `*.domain.com` pattern
4. ✓ SAN certificates include all specified DNS and IP entries
5. ✓ Certificate chain validation correctly identifies valid and invalid chains
6. ✓ Remote certificate download works with standard TLS servers
7. ✓ Both PEM and DER formats are correctly handled
8. ✓ Private keys are generated in PEM format
9. ✓ Error messages are clear and actionable
10. ✓ Help text is available for all commands and flags
