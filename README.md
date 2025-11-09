# SSH CA Certificate Signing Service

A secure HTTPS service for signing SSH public keys with a Certificate Authority, using systemd secrets for key storage and SQLite for user authentication and audit logging.

## Quick Start

### Development Setup

```bash
# Generate a test CA key
ssh-keygen -t ed25519 -f ./tmp/test_ca -N "" -C "Test CA"

# Initialize database and create first user
./sshcad init

# Start the server
./sshcad serve
```

## API Reference

### Get CA Public Key

```bash
GET /api/v1/ca.pub
```

Returns the CA public key that can be added to `~/.ssh/known_hosts` or SSH server configurations.

**Example (development):**
```bash
curl -k https://localhost:8443/api/v1/ca.pub
```

### Sign SSH Certificate

```bash
POST /api/v1/sign
```

Signs an SSH public key and returns a certificate.

**Authentication:** Basic Auth (username:password)

**Request Body:**
```json
{
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
  "hostname": "myhost"
}
```

**Response:**
```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAIHNza...",
  "serial": 1,
  "expires_at": "2025-10-27T10:21:45Z"
}
```

**Example (development):**
```bash
curl -k -X POST https://localhost:8443/api/v1/sign \
  -u alice:password \
  -H "Content-Type: application/json" \
  -d "{\"public_key\": \"$(< ~/.ssh/id_ed25519.pub)\", \"hostname\": \"$(hostname)\"}"
```

### Health Check

```bash
curl -k https://localhost:8443/health
```

Returns service health status.

## Configuration

Configuration is loaded from environment variables, typically set in `/etc/default/sshcad`.

| Variable            | Default          | Description                                           |
| ----------          | ---------        | -------------                                         |
| `SSHCA_LISTEN_ADDR` | `:8443`          | Address to listen on (use localhost with Caddy)       |
| `SSHCA_TLS_CERT`    | `./tmp/cert.pem` | TLS certificate path (auto-generated Ed25519 for dev) |
| `SSHCA_TLS_KEY`     | `./tmp/key.pem`  | TLS private key path (auto-generated Ed25519 for dev) |
| `SSHCA_DB_PATH`     | `./tmp/sshca.db` | SQLite database path                                  |
| `SSHCA_PRINCIPALS`  | `root`           | SSH certificate principals                            |
| `SSHCA_VALIDITY`    | `-1m:+1h`        | Certificate validity period                           |

## CLI Commands

### `sshcad init`
Initialize the database and create the first user. Prompts for username and password interactively (or reads from stdin if not a TTY). This is a no-op if users already exist in the database.

**Interactive usage:**
```bash
./sshcad init
```

**Non-interactive usage (for scripting/testing):**
```bash
echo -e "alice\npassword" | ./sshcad init
```

### `sshcad add-user <username>`
Add a new user with interactive password prompt. Use this to add additional users after initialization.

### `sshcad serve`
Start the HTTPS server.

## Client Usage Example

After signing, save the certificate and use it for SSH:

```bash
# Get signed certificate (production)
curl -X POST https://sshca.example.com/api/v1/sign \
  -u alice:password \
  -H "Content-Type: application/json" \
  -d "{\"public_key\": \"$(cat ~/.ssh/id_ed25519.pub)\", \"hostname\": \"$(hostname)\"}" \
  | jq -r '.certificate' > ~/.ssh/id_ed25519-cert.pub

# SSH will automatically use the certificate if it's named <key>-cert.pub
ssh user@server
```

## Deployment Files

- `configs/Caddyfile.example` - Caddy reverse proxy configuration with automatic HTTPS
- `configs/sshcad.example` - Environment variables for sshcad
