# Deploying Orchesis

## Quick Start (Docker)
```bash
cp .env.example .env
# Edit .env: set ORCHESIS_API_TOKEN
docker compose up -d
```

## Architecture
- orchesis-api (port 8080): Control plane API
- orchesis-proxy (port 9000): MCP enforcement proxy
- Shared volume: policy, state, decisions log

## Configuration
- policy.yaml mounted read-only
- API_TOKEN for authentication
- LOG_LEVEL: DEBUG, INFO, WARN, ERROR

## Health Checks
- GET http://localhost:8080/api/v1/status
- GET http://localhost:8080/health
- GET http://localhost:8080/metrics (Prometheus)

## Running Fuzzer
```bash
docker compose --profile testing run --rm orchesis-fuzzer
```

## Production Checklist
- [ ] Set strong API_TOKEN
- [ ] Use strict.yaml or custom policy
- [ ] Enable webhook notifications
- [ ] Configure log retention
- [ ] Monitor /metrics endpoint
- [ ] Run nightly fuzzer via CI
