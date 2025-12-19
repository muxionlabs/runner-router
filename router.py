"""
FastAPI Stream-Based Load Balancer with Auto-Generated Self-Signed Certificates

This implements the same stream-based load balancing logic as the Caddy plugin:
- Assigns upstreams based on X-Stream-Id header
- Removes assigned upstreams from rotation
- Releases upstreams via /stream/stop endpoint
- Auto-generates self-signed SSL certificates on startup
"""

import asyncio
import httpx
import logging
import os
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
import uvicorn


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class UpstreamInfo:
    """Information about an upstream server"""
    url: str
    available: bool = True
    stream_id: Optional[str] = None
    assigned_at: Optional[datetime] = None


@dataclass
class Session:
    """Active stream session"""
    stream_id: str
    upstream_url: str
    assigned_at: datetime
    timer_task: Optional[asyncio.Task] = None


class StreamLoadBalancer:
    """
    Stream-based load balancer that assigns exclusive upstreams to stream IDs
    """

    def __init__(self, upstreams: List[str], session_timeout: int = 0):
        """
        Initialize the load balancer

        Args:
            upstreams: List of upstream URLs
            session_timeout: Session timeout in seconds (default: 0 = no timeout)
        """
        self.upstreams: Dict[str, UpstreamInfo] = {
            url: UpstreamInfo(url=url) for url in upstreams
        }
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = session_timeout
        self.client: Optional[httpx.AsyncClient] = None

        logger.info(f"Initialized load balancer with {len(upstreams)} upstreams")
        if session_timeout > 0:
            logger.info(f"Session timeout: {session_timeout} seconds")
        else:
            logger.info("Session timeout: disabled (sessions never auto-expire)")

    async def start(self):
        """Start the load balancer"""
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True
        )
        logger.info("Load balancer started")

    async def stop(self):
        """Stop the load balancer and cleanup"""
        # Cancel all timer tasks
        for session in self.sessions.values():
            if session.timer_task:
                session.timer_task.cancel()

        # Close HTTP client
        if self.client:
            await self.client.aclose()

        logger.info("Load balancer stopped")

    def get_stats(self) -> dict:
        """Get current load balancer statistics"""
        available_count = sum(1 for u in self.upstreams.values() if u.available)

        return {
            "total_upstreams": len(self.upstreams),
            "available_upstreams": available_count,
            "active_sessions": len(self.sessions),
            "upstreams": [
                {
                    "url": info.url,
                    "available": info.available,
                    "stream_id": info.stream_id,
                    "assigned_at": info.assigned_at.isoformat() if info.assigned_at else None
                }
                for info in self.upstreams.values()
            ]
        }

    async def check_upstream_idle(self, upstream_url: str) -> bool:
        """
        Check if an upstream is idle by pinging its /health endpoint

        Args:
            upstream_url: The upstream URL to check

        Returns:
            True if upstream returns {"status": "IDLE"}, False otherwise
        """
        try:
            health_url = f"{upstream_url}/health"
            response = await self.client.get(health_url, timeout=5.0)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get("status") == "IDLE":
                        logger.debug(f"Upstream {upstream_url} is IDLE")
                        return True
                    else:
                        logger.debug(f"Upstream {upstream_url} status: {data.get('status')}")
                        return False
                except Exception as e:
                    logger.warning(f"Failed to parse JSON from {health_url}: {e}")
                    return False
            else:
                logger.warning(f"Health check failed for {upstream_url}: status {response.status_code}")
                return False

        except httpx.RequestError as e:
            logger.warning(f"Health check request failed for {upstream_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking {upstream_url}: {e}")
            return False

    async def get_upstream(self, stream_id: str) -> str:
        """
        Get the assigned upstream for a stream (does not assign new ones)

        Args:
            stream_id: The stream identifier

        Returns:
            The assigned upstream URL

        Raises:
            HTTPException: If stream doesn't have an active session
        """
        if stream_id not in self.sessions:
            raise HTTPException(
                status_code=404,
                detail=f"No active session for stream {stream_id}. Call /stream/start first."
            )

        session = self.sessions[stream_id]

        # Reset the timeout timer to keep session alive (only if timeout enabled)
        if session.timer_task:
            session.timer_task.cancel()

        if self.session_timeout > 0:
            session.timer_task = asyncio.create_task(
                self._session_timeout(stream_id)
            )

        logger.debug(f"Using existing upstream for stream {stream_id}: {session.upstream_url}")
        return session.upstream_url

    async def assign_upstream(self, stream_id: str, allow_existing: bool = False) -> str:
        """
        Assign an available upstream to a stream ID

        Args:
            stream_id: The stream identifier
            allow_existing: If True, return existing session; if False, error on existing

        Returns:
            The assigned upstream URL

        Raises:
            HTTPException: If no upstreams are available or stream already exists
        """
        # Check if stream already has an assignment
        if stream_id in self.sessions:
            if not allow_existing:
                raise HTTPException(
                    status_code=409,
                    detail=f"Stream {stream_id} already has an active session. Call /stream/stop first."
                )

            session = self.sessions[stream_id]

            # Reset the timeout timer (only if timeout is enabled)
            if session.timer_task:
                session.timer_task.cancel()

            if self.session_timeout > 0:
                session.timer_task = asyncio.create_task(
                    self._session_timeout(stream_id)
                )

            logger.debug(f"Returning existing upstream for stream {stream_id}: {session.upstream_url}")
            return session.upstream_url

        # Find an available upstream
        available_upstream = None
        for upstream in self.upstreams.values():
            if upstream.available:
                # Check if upstream is actually idle
                is_idle = await self.check_upstream_idle(upstream.url)
                if is_idle:
                    available_upstream = upstream
                    break
                else:
                    logger.warning(f"Upstream {upstream.url} is marked available but not IDLE, skipping")

        if not available_upstream:
            logger.warning(f"No idle upstreams available for stream {stream_id}")
            raise HTTPException(
                status_code=503,
                detail="No idle upstreams available"
            )

        # Assign the upstream
        now = datetime.now()
        available_upstream.available = False
        available_upstream.stream_id = stream_id
        available_upstream.assigned_at = now

        # Create session with timeout (only if enabled)
        timer_task = None
        if self.session_timeout > 0:
            timer_task = asyncio.create_task(self._session_timeout(stream_id))

        self.sessions[stream_id] = Session(
            stream_id=stream_id,
            upstream_url=available_upstream.url,
            assigned_at=now,
            timer_task=timer_task
        )

        timeout_msg = f"(timeout: {self.session_timeout}s)" if self.session_timeout > 0 else "(no timeout)"
        logger.info(
            f"Assigned upstream {available_upstream.url} to stream {stream_id} {timeout_msg}"
        )

        return available_upstream.url

    async def release_session(self, stream_id: str) -> bool:
        """
        Release an upstream back to the pool

        Args:
            stream_id: The stream identifier to release

        Returns:
            True if session was released, False if not found
        """
        if stream_id not in self.sessions:
            logger.warning(f"Attempted to release non-existent session: {stream_id}")
            return False

        session = self.sessions[stream_id]

        # Cancel timeout timer
        if session.timer_task:
            session.timer_task.cancel()

        # Mark upstream as available
        if session.upstream_url in self.upstreams:
            upstream = self.upstreams[session.upstream_url]
            upstream.available = True
            upstream.stream_id = None
            upstream.assigned_at = None

        # Remove session
        duration = (datetime.now() - session.assigned_at).total_seconds()
        del self.sessions[stream_id]

        logger.info(
            f"Released upstream {session.upstream_url} from stream {stream_id} "
            f"(duration: {duration:.2f}s)"
        )

        return True

    async def _session_timeout(self, stream_id: str):
        """Handle session timeout"""
        try:
            await asyncio.sleep(self.session_timeout)
            logger.warning(f"Session timeout for stream {stream_id}")
            await self.release_session(stream_id)
        except asyncio.CancelledError:
            # Timer was cancelled, which is normal
            pass

    async def proxy_request(
        self,
        stream_id: str,
        path: str,
        method: str,
        headers: dict,
        body: Optional[bytes] = None,
        is_start: bool = False
    ) -> httpx.Response:
        """
        Proxy a request to the assigned upstream

        Args:
            stream_id: The stream identifier
            path: Request path
            method: HTTP method
            headers: Request headers
            body: Request body (optional)
            is_start: True if this is /stream/start (allows new assignment)

        Returns:
            The upstream response
        """
        if is_start:
            upstream_url = await self.assign_upstream(stream_id, allow_existing=False)
        else:
            upstream_url = await self.get_upstream(stream_id)
        target_url = f"{upstream_url}{path}"

        # Remove hop-by-hop headers
        headers_to_send = {
            k: v for k, v in headers.items()
            if k.lower() not in ['host', 'connection', 'keep-alive', 'transfer-encoding']
        }

        logger.debug(f"Proxying {method} {path} to {target_url} for stream {stream_id}")

        try:
            response = await self.client.request(
                method=method,
                url=target_url,
                headers=headers_to_send,
                content=body
            )
            return response
        except httpx.RequestError as e:
            logger.error(f"Error proxying request to {target_url}: {e}")
            raise HTTPException(
                status_code=502,
                detail=f"Bad Gateway: {str(e)}"
            )


def generate_self_signed_cert(cert_path: Path, key_path: Path):
    """
    Generate a self-signed certificate and private key

    Args:
        cert_path: Path to save the certificate
        key_path: Path to save the private key
    """
    logger.info("Generating self-signed certificate...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate with minimal information
    # Only Common Name is required, all other fields left blank
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Certificate saved to: {cert_path}")
    logger.info(f"Private key saved to: {key_path}")


# Global load balancer instance
lb: Optional[StreamLoadBalancer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI
    Handles startup and shutdown events
    """
    global lb

    # Startup
    logger.info("Starting Stream Load Balancer...")

    # Initialize load balancer with upstream servers from RUNNERS env var
    runners_env = os.getenv("RUNNERS", "")

    if not runners_env:
        logger.error("RUNNERS environment variable not set")
        raise ValueError("RUNNERS environment variable is required (comma-delimited list of upstream URLs)")

    # Parse comma-delimited RUNNERS
    upstreams = [url.strip() for url in runners_env.split(",") if url.strip()]

    if not upstreams:
        logger.error("No valid upstreams found in RUNNERS environment variable")
        raise ValueError("RUNNERS must contain at least one valid upstream URL")

    logger.info(f"Loaded {len(upstreams)} upstreams from RUNNERS: {upstreams}")

    lb = StreamLoadBalancer(
        upstreams=upstreams,
        session_timeout=int(os.getenv("SESSION_TIMEOUT", "0"))  # Default: 0 = no timeout
    )

    await lb.start()

    # Register to orchestrator
    from register_worker import register_to_orchestrator
    registered = register_to_orchestrator()
    if not registered:
        logger.error("Failed to register to Orchestrator")
        raise ValueError("Failed to register to Orchestrator")

    yield

    # Shutdown
    logger.info("Shutting down Stream Load Balancer...")
    await lb.stop()


# Create FastAPI app
app = FastAPI(
    title="Stream Load Balancer",
    description="Stream-based load balancer with exclusive upstream assignment",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/stats")
async def get_stats():
    """Get load balancer statistics"""
    return lb.get_stats()


@app.post("/stream/start")
async def start_stream(
    request: Request,
    x_stream_id: Optional[str] = Header(None)
):
    """
    Start a stream and assign an upstream

    Headers:
        X-Stream-Id: The stream identifier
    """
    if not x_stream_id:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Stream-Id header"
        )

    # Read request body
    body = await request.body()

    # This will assign a new upstream (or error if already assigned)
    response = await lb.proxy_request(
        stream_id=x_stream_id,
        path="/stream/start",
        method=request.method,
        headers=dict(request.headers),
        body=body if body else None,
        is_start=True
    )

    # Filter out problematic headers that cause Content-Length mismatch
    response_headers = {}
    for key, value in response.headers.items():
        if key.lower() not in ['content-length', 'content-encoding', 'transfer-encoding']:
            response_headers[key] = value

    # Return raw response content
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type", "application/octet-stream")
    )


@app.post("/stream/stop")
async def stop_stream(
    request: Request,
    x_stream_id: Optional[str] = Header(None)
):
    """
    Release an upstream from a stream

    Headers:
        X-Stream-Id: The stream identifier to release
    """
    if not x_stream_id:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Stream-Id header"
        )

    body = await request.body()

    # Proxy stop request to upstream
    response = await lb.proxy_request(
        stream_id=x_stream_id,
        path="/stream/stop",
        method=request.method,
        headers=dict(request.headers),
        body=body if body else None,
        is_start=False
    )

    # Release the session from load balancer
    released = await lb.release_session(x_stream_id)

    if not released:
        logger.warning(f"Session {x_stream_id} was not found during stop")

    # Filter out problematic headers
    response_headers = {}
    for key, value in response.headers.items():
        if key.lower() not in ['content-length', 'content-encoding', 'transfer-encoding']:
            response_headers[key] = value

    # Return raw response content
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type", "application/octet-stream")
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_api(
    request: Request,
    path: str,
    x_stream_id: Optional[str] = Header(None)
):
    """
    Proxy requests to assigned upstream

    Note: Stream must be started with /stream/start first

    Headers:
        X-Stream-Id: The stream identifier
    """
    if not x_stream_id:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Stream-Id header"
        )

    # Read request body
    body = await request.body()

    # Proxy the request (will error if stream not started)
    response = await lb.proxy_request(
        stream_id=x_stream_id,
        path=f"/{path}",
        method=request.method,
        headers=dict(request.headers),
        body=body if body else None,
        is_start=False
    )

    # Filter out problematic headers that cause Content-Length mismatch
    response_headers = {}
    for key, value in response.headers.items():
        if key.lower() not in ['content-length', 'content-encoding', 'transfer-encoding']:
            response_headers[key] = value

    # Return raw response content to avoid Content-Length issues
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type", "application/octet-stream")
    )


if __name__ == "__main__":
    # Generate certificates before starting uvicorn
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)

    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if not cert_path.exists() or not key_path.exists():
        logger.info("Generating self-signed certificates before startup...")
        generate_self_signed_cert(cert_path, key_path)
    else:
        logger.info(f"Using existing certificates from {cert_dir}")

    # Run with uvicorn - use app object directly
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("ROUTER_PORT", "8443")),
        ssl_keyfile=str(key_path),
        ssl_certfile=str(cert_path),
        reload=False,
        log_level="info"
    )
