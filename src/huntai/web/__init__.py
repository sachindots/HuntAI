"""FastAPI web layer — REST + WebSocket over the shared core engine."""

from .app import create_app

__all__ = ["create_app"]
