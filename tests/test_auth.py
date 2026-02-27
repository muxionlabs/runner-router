"""
Tests for AuthMiddleware in router.py
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from router import AuthMiddleware


class TestAuthMiddleware:
    """Test cases for AuthMiddleware"""

    @pytest.fixture
    def mock_app(self):
        """Create a mock FastAPI app"""
        app = FastAPI()
        return app

    @pytest.fixture
    def auth_middleware(self, mock_app):
        """Create AuthMiddleware with test token"""
        os.environ["AUTH_TOKEN"] = "test-secret-token"
        middleware = AuthMiddleware(mock_app)
        return middleware

    @pytest.fixture
    def mock_scope(self):
        """Create a basic HTTP scope"""
        return {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [],
        }

    @pytest.fixture
    def mock_receive(self):
        """Create a mock receive function"""
        return AsyncMock()

    @pytest.fixture
    def mock_send(self):
        """Create a mock send function"""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_request_without_auth_header_returns_401(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that request without Authorization header returns 401"""
        # No Authorization header in scope
        mock_scope["headers"] = []

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that 401 response was sent (called twice: start + body)
        assert mock_send.call_count >= 1
        response = mock_send.call_args_list[0][0][0]
        assert response["type"] == "http.response.start"
        assert response["status"] == 401

    @pytest.mark.asyncio
    async def test_request_with_invalid_token_returns_401(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that request with invalid token returns 401"""
        mock_scope["headers"] = [
            (b"authorization", b"Bearer wrong-token")
        ]

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that 401 response was sent (called twice: start + body)
        assert mock_send.call_count >= 1
        response = mock_send.call_args_list[0][0][0]
        assert response["type"] == "http.response.start"
        assert response["status"] == 401

    @pytest.mark.asyncio
    async def test_request_with_valid_bearer_token_passes(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that request with valid Bearer token passes through"""
        mock_scope["headers"] = [
            (b"authorization", b"Bearer test-secret-token")
        ]

        # Mock the app to return a response
        auth_middleware.app = AsyncMock()
        auth_middleware.app.return_value = AsyncMock()

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that the app was called (auth passed)
        auth_middleware.app.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_with_valid_token_no_bearer_passes(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that request with valid token (no Bearer) passes through"""
        mock_scope["headers"] = [
            (b"authorization", b"test-secret-token")
        ]

        # Mock the app to return a response
        auth_middleware.app = AsyncMock()

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that the app was called (auth passed)
        auth_middleware.app.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_endpoint_excluded_from_auth(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that /health endpoint bypasses auth"""
        mock_scope["path"] = "/health"
        mock_scope["headers"] = []  # No auth header

        # Mock the app to return a response
        auth_middleware.app = AsyncMock()

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that the app was called (auth bypassed)
        auth_middleware.app.assert_called_once()

    @pytest.mark.asyncio
    async def test_auth_skipped_when_token_not_configured(
        self, mock_app, mock_scope, mock_receive, mock_send
    ):
        """Test that auth is skipped when AUTH_TOKEN is not set"""
        # Remove AUTH_TOKEN from environment
        original_token = os.environ.pop("AUTH_TOKEN", None)
        try:
            middleware = AuthMiddleware(mock_app)
            mock_scope["headers"] = []  # No auth header

            # Mock the app to return a response
            middleware.app = AsyncMock()

            await middleware(mock_scope, mock_receive, mock_send)

            # Check that the app was called (auth skipped)
            middleware.app.assert_called_once()
        finally:
            # Restore original token
            if original_token:
                os.environ["AUTH_TOKEN"] = original_token

    @pytest.mark.asyncio
    async def test_invalid_api_key_returns_401(
        self, auth_middleware, mock_scope, mock_receive, mock_send
    ):
        """Test that invalid API key returns 401 with specific message"""
        mock_scope["headers"] = [
            (b"authorization", b"invalid-key")
        ]

        await auth_middleware(mock_scope, mock_receive, mock_send)

        # Check that 401 response was sent (called twice: start + body)
        assert mock_send.call_count >= 1
        response = mock_send.call_args_list[0][0][0]
        assert response["type"] == "http.response.start"
        assert response["status"] == 401