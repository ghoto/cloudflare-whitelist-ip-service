# Cloudflare IP Whitelist Service

A high-performance web application that allows users to temporarily whitelist their IP address in a Cloudflare Zero Trust Access Policy with automatic expiration.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?logo=go)
![Node Version](https://img.shields.io/badge/node-20+-339933?logo=node.js)

## Features

### Core Functionality
- **Automatic IP Detection**: Detects user IP from `CF-Connecting-IP`, `X-Forwarded-For`, or `RemoteAddr` headers
- **Public IP Fallback**: When running locally (Docker), automatically fetches public IP via `api.ipify.org`
- **IP Validation**: Validates IP addresses before updating policies (supports IPv4 and IPv6)
- **Temporary Whitelisting**: Set expiration times (1 hour, 4 hours, 8 hours, or 24 hours)

### IP Status Management
- **Status Display**: Shows if your IP is currently whitelisted with time remaining
- **Extend Time**: Easily extend your whitelist duration without re-adding
- **Remove Access**: Instantly remove your IP from the whitelist
- **Human-Readable Time**: Displays time as "2 hours 15 minutes" instead of "2h15m0s"

### Reliability
- **Persistent Storage**: Whitelist data survives container restarts using Docker volumes
- **Background Expiry Daemon**: Automatically removes expired IPs every 10 seconds
- **Restart-Safe**: Loads existing whitelists on startup and continues tracking expiry

## Tech Stack

### Backend
- **Language**: [Golang](https://go.dev/) 1.21+ (High concurrency and performance)
- **Router**: [Chi v5](https://github.com/go-chi/chi) (Lightweight HTTP router)
- **Dependencies**:
  - `github.com/go-chi/chi/v5` - HTTP router
  - `github.com/go-chi/cors` - CORS middleware

### Frontend
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Framework**: [Vite](https://vitejs.dev/) + [React](https://react.dev/)
- **UI Library**: [Mantine v7](https://mantine.dev/) (Rich, accessible components)

## Prerequisites

- **Cloudflare Account** with Zero Trust Access
- **Cloudflare API Token** with permissions to modify Access policies
- **Docker** and **Docker Compose** (for containerized deployment)
- **Go 1.21+** and **Node.js 20+** (for local development)

## Quick Start

### 1. Configure Environment Variables

Create `.env` in the project root:

```env
CLOUDFLARE_API_TOKEN=your_api_token_here
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_POLICY_ID=your_policy_id
PORT=8080
```

> **Tip**: Copy `.env.template` to `.env` and fill in your values.

### 2. Run with Docker Compose

```bash
docker-compose up --build -d
```

The service will be available at `http://localhost:8080`

**Or use the pre-built Docker image from GitHub Container Registry:**

```bash
docker pull ghcr.io/ghoto/cloudflare-whitelist-ip-service:master
```

### 3. Access the Application

1. Visit `http://localhost:8080` in your browser
2. Your IP will be automatically detected
3. Select a duration and click "Whitelist IP"
4. Your IP is now added to the Cloudflare Access Policy

## API Endpoints

### `GET /ip`
Returns the detected client IP address.

**Response:**
```json
{
  "ip": "1.2.3.4"
}
```

### `GET /status`
Check if the current IP is whitelisted and get expiry information.

**Response:**
```json
{
  "ip": "1.2.3.4",
  "whitelisted": true,
  "expiresAt": "2025-12-20T18:00:00Z",
  "timeRemaining": "2 hours 15 minutes"
}
```

### `POST /whitelist`
Whitelist the current IP or extend existing whitelist.

**Request:**
```json
{
  "duration": "60"  // minutes
}
```

**Response:**
```json
{
  "message": "Success",
  "ip": "1.2.3.4"
}
```

### `DELETE /whitelist`
Remove the current IP from the whitelist.

**Response:**
```json
{
  "message": "IP removed from whitelist",
  "ip": "1.2.3.4"
}
```

## Development

### Local Development (without Docker)

#### Backend
```bash
cd backend
go mod download
go run main.go
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
cd backend
go test -v
```

## Docker Commands

Using the provided `Makefile`:

- **Build Image**: `make build`
- **Run Service**: `make run`
- **Stop Service**: `make stop`

Or use Docker Compose directly:

```bash
# Build and start
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## Deployment

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Access policy permissions | Yes |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID | Yes |
| `CLOUDFLARE_POLICY_ID` | The Access Policy ID to modify | Yes |
| `PORT` | Server port (default: 8080) | No |

### Finding Your Policy ID

Use the included debug scripts:

```bash
node scripts/list_all_policies.js
```

## Architecture

### Persistence
- Whitelist data is stored in `whitelist_store.json`
- Docker volume `whitelist-data` ensures data survives container restarts
- Background daemon checks for expired IPs every 10 seconds

### IP Detection Priority
1. `CF-Connecting-IP` header (Cloudflare)
2. `X-Forwarded-For` header (Proxies)
3. `RemoteAddr` (Direct connection)
4. Public IP lookup (if private IP detected)

## Security

- `.env` files are gitignored
- Pre-commit hooks prevent committing secrets
- IP validation prevents malformed addresses
- CORS configured for production use

## Contributing

1. Install pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
```

2. Make your changes
3. Run tests: `go test -v`
4. Commit with conventional commits format

## License

MIT

## Support

For issues and questions, please open an issue on GitHub.
