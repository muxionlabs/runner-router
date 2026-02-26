# BYOC Runner Router

A Python-based router for Livepeer BYOC (Bring Your Own Computer) that manages runner registration and traffic routing to your self-hosted compute nodes.

## Prerequisites

- Docker
- Docker Compose
- Python 3.11+ (for local development)

## Building the Docker Container

Build the Docker image with the tag `byoc-runner-router:latest`:

```powershell
docker build -f Dockerfile.router -t byoc-runner-router:latest .
```

Or using Docker Compose, which automatically tags the image:

```powershell
docker-compose build
```

## Environment Variables

The router requires the following environment variables to function:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RUNNERS` | Comma-separated list of available runners | `runner1.example.com:8000,runner2.example.com:8001` |
| `ORCH_SERVICE_ADDR` | Orchestrator URL to connect to | `orchestrator.your-url.io:8935` |
| `ORCH_SECRET` | Secret for orchestrator authentication | `your-orchestrator-secret-key` |
| `CAPABILITY_NAME` | BYOC capability name | `byoc-compute (get this from the runner)` |
| `CAPABILITY_URL` | Publicly available URL for the Orchestrator to send work to | `https://your-router.example.co:9099` |
| `CAPABILITY_PRICE_PER_UNIT` | Price per unit in the specified currency | `1000` |
| `CAPABILITY_CAPACITY` | Total capacity of all runners | `10` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ROUTER_PORT` | Port the router listens on | `9099` |
| `REG_INTERVAL_SECONDS` | How often to re-register with Orchestrator | `60` |
| `AUTH_TOKEN` | Authorization token for router API (if not set, authorization is disabled) | None |
| `CAPABILITY_DESCRIPTION` | Description of the capability | Empty |
| `CAPABILITY_PRICE_SCALING` | Price scaling factor | `1` |
| `CAPABILITY_PRICE_CURRENCY` | Currency for pricing (WEI, ETH, or USD) | `WEI` |

## Configuration Methods

### Method 1: Using .env File

1. Copy the template file:

```
cp .env.template .env
```

2. Edit `.env` and fill in your values:

```powershell
# Example .env file
RUNNERS=runner1.example.com:8000,runner2.example.com:8001
ROUTER_PORT=9099
REG_INTERVAL_SECONDS=60
ORCH_SERVICE_ADDR=orchestrator.your-url.io:8935
ORCH_SECRET=your-orchestrator-secret-key
AUTH_TOKEN=your-runner-router-auth-token
CAPABILITY_CAPACITY=10
CAPABILITY_NAME=byoc-compute
CAPABILITY_DESCRIPTION=My BYOC runners
CAPABILITY_URL=https://your-router.example.com
CAPABILITY_PRICE_PER_UNIT=1000
CAPABILITY_PRICE_SCALING=1
CAPABILITY_PRICE_CURRENCY=WEI
```

### Method 2: Using Docker Compose

The `docker-compose.yml` is pre-configured to use environment variables from a `.env` file. Simply ensure your `.env` file is populated and run:

```powershell
docker-compose up -d
```

### Method 3: Manual Docker Run

```
docker run -d `
  --name byoc-stream-runner-router `
  -p 9099:9099 `
  -e RUNNERS=runner1.example.com,runner2.example.com `
  -e ORCH_SERVICE_ADDR=orchestrator.livepeer.io `
  -e ORCH_SECRET=your-secret-key `
  -e CAPABILITY_NAME=byoc-compute `
  -e CAPABILITY_URL=https://your-router.example.com `
  -e CAPABILITY_PRICE_PER_UNIT=1000 `
  -e CAPABILITY_CAPACITY=10 `
  byoc-runner-router:latest
```

## Running the Container

### Using Docker Compose

```
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Using Docker Directly

```
docker run -d `
  --network byoc-runners `
  -p 9099:9099 `
  --env-file .env `
  byoc-runner-router:latest
```

**Note**: The container expects to be on a Docker network named `byoc-runners`. If this network doesn't exist, create it first:

```
docker network create byoc-runners
```

## Local Development

Install dependencies and run locally:

```
pip install -r requirements.txt
copy .env.template .env
# Edit .env with your configuration
python router.py
```

## Project Structure

- [`router.py`](router.py) - Main router application
- [`register_worker.py`](register_worker.py) - Worker registration logic
- [`Dockerfile.router`](Dockerfile.router) - Docker image definition
- [`docker-compose.yml`](docker-compose.yml) - Docker Compose configuration
- [`.env.template`](.env.template) - Environment variable template
- [`requirements.txt`](requirements.txt) - Python dependencies