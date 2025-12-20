# Cloudflare IP Whitelist Service

A high-performance web application that allows users to temporarily whitelist their IP address in a Cloudflare Access policy or Firewall rule.

## Tech Stack

### Backend
- **Language**: [Golang](https://go.dev/) (Chosen for high concurrency and performance)
- **Dependencies**:
  - Cloudflare Go SDK
  - High-performance HTTP router (e.g., standard library or Chi)

### Frontend
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Framework**: [Vite](https://vitejs.dev/) + [React](https://react.dev/)
- **UI Library**: [Mantine](https://mantine.dev/) (Rich, accessible components)

## Features
- **One-click Whitelisting**: Detects user IP and updates Cloudflare policy.
- **Temporary Access**: Automatically expires access after a set duration (TTL).
- **High Performance**: Minimal latency for policy updates and UI rendering.

## Development Setup

### Prerequisites
- Go 1.21+
- Node.js 20+
- Cloudflare API Token with permissions to modify Access policies or Firewall rules.

### Running Locally

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

## Configuration
Environment variables required:
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `CLOUDFLARE_POLICY_ID` (or equivalent target)

## Docker Support

We provide a `Makefile` for convenient Docker operations:

- **Build Image**: `make build`
- **Run Service**: `make run`
- **Stop Service**: `make stop`
