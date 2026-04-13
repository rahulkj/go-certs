# go-certs

CLI tool for managing TLS certificates - generate, validate, download, and inspect certificates.

## Features

- Generate self-signed root CA certificates
- Generate server certificates (leaf, SAN, or wildcard)
- Generate wildcard certificates with automatic root CA
- Sign server certificates with existing CA
- Validate certificate chains from local files
- Validate certificate and private key pairs match
- Scan folder for certificates and display CN/SAN info
- Download and validate certificate chains from remote servers
- Inspect certificate details (including SANs)
- Support for RSA (2048, 4096) and ECDSA (P-256) keys
- Output certificates in PEM format with optional chain

## Installation

### From Release

Download the appropriate binary for your platform from the [releases](https://github.com/rahulkj/go-certs/releases).

### From Source

```bash
go install github.com/rahulkj/go-certs@latest
```

Or build locally:

```bash
git clone https://github.com/rahulkj/go-certs.git
cd go-certs
go build -o go-certs .
```

## Usage

### Generate Root CA

```bash
# Generate a self-signed root CA
go-certs generate root --cn "My Root CA" --out root.crt --key-out root.key
```

### Generate Server Certificates

The `generate server` command handles all server certificate types:

```bash
# Generate a self-signed server certificate
go-certs generate server --cn "example.com" --out server.crt --key-out server.key

# Generate a server certificate with SANs
go-certs generate server --cn "api.example.com" \
  --san-dns "api.example.com" \
  --san-dns "www.example.com" \
  --san-ip "1.2.3.4" \
  --out server.crt \
  --key-out server.key

# Generate a wildcard certificate (creates new root CA automatically)
go-certs generate server --cn example.com --wildcard --out server.crt --key-out server.key

# Generate a server certificate signed by an existing CA
go-certs generate server --cn "api.example.com" \
  --ca-cert root.crt \
  --ca-key root.key \
  --out server.crt \
  --key-out server.key
```

### Validate Certificates

```bash
# Validate a local certificate chain (provide certs in order: leaf -> intermediate -> root)
go-certs validate chain --certs server.crt --certs root.crt

# Validate remote certificate chain
go-certs validate remote --host "example.com" --port 443

# Validate certificate and private key match
go-certs validate pair --cert server.crt --key server.key

# Scan folder for certificates and display CN/SAN info
go-certs validate folder --dir ./certs
```

### Download Certificates

```bash
# Download certificate chain from remote host
go-certs download chain --host "example.com" --out-dir ./certs
```

### Inspect Certificates

```bash
# View certificate details including SANs
go-certs inspect --cert server.crt
```

## Command Options

### Generate Root

| Flag | Description | Default |
|------|-------------|---------|
| `--cn` | Common Name (required) | - |
| `--key-type` | Key type (rsa, ecdsa) | rsa |
| `--key-size` | Key size (2048, 4096 for RSA) | 2048 |
| `--days` | Validity period in days | 365 |
| `--out` | Output certificate file | stdout |
| `--key-out` | Output private key file | stdout |

### Generate Server

| Flag | Description | Default |
|------|-------------|---------|
| `--cn` | Common Name (required) | - |
| `--out` | Output certificate file (required) | - |
| `--key-out` | Output private key file | stdout |
| `--key-type` | Key type (rsa, ecdsa) | rsa |
| `--key-size` | Key size (2048, 4096 for RSA) | 2048 |
| `--days` | Validity period in days | 365 |
| `--san-dns` | DNS names for SAN (repeatable) | - |
| `--san-ip` | IP addresses for SAN (repeatable) | - |
| `--ca-cert` | CA certificate to sign with | - |
| `--ca-key` | CA private key to sign with | - |
| `--wildcard` | Generate wildcard certificate | false |

### Validate

| Flag | Description | Default |
|------|-------------|---------|
| `--certs` | Certificate files (validate chain, repeatable) | - |
| `--host` | Remote hostname (validate remote) | - |
| `--port` | Remote port | 443 |
| `--cert` | Certificate file (validate pair/folder) | - |
| `--key` | Private key file (validate pair) | - |
| `--dir` | Directory to scan (validate folder) | - |

### Download

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Remote hostname (required) | - |
| `--port` | Remote port | 443 |
| `--out-dir` | Output directory | ./certs |

## Output Files

### Self-signed Server
- `server.crt` - Server certificate
- `server.key` - Server private key

### Wildcard
- `server.crt` - Server certificate + root CA chain
- `server.key` - Server private key
- `server.crt.root.crt` - Root CA certificate
- `server.key.root.key` - Root CA private key

### CA-signed Server
- `server.crt` - Server certificate + CA chain
- `server.key` - Server private key

## License

MIT