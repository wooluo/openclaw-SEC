"""
OpenClaw Security Shield - Cloud API
FastAPI backend for the SaaS management platform
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import uvicorn
from loguru import logger
import sys
from datetime import datetime

from .auth import get_current_user, User, TokenData
from .assets import router as assets_router
from .alerts import router as alerts_router
from .policies import router as policies_router
from .monitoring import router as monitoring_router


# Configure logger
logger.remove()
logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("Starting OpenClaw Security Shield API...")
    # Startup
    yield
    # Shutdown
    logger.info("Shutting down OpenClaw Security Shield API...")


# Create FastAPI app
app = FastAPI(
    title="OpenClaw Security Shield API",
    description="Cloud security management platform for OpenClaw",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Security
security = HTTPBearer(auto_error=False)


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.1.0"
    }


# API info endpoint
@app.get("/", tags=["Info"])
async def api_info():
    """API information endpoint."""
    return {
        "name": "OpenClaw Security Shield API",
        "version": "1.1.0",
        "description": "Cloud security management platform",
        "endpoints": {
            "assets": "/api/v1/assets",
            "alerts": "/api/v1/alerts",
            "policies": "/api/v1/policies",
            "monitoring": "/api/v1/monitoring",
            "docs": "/docs"
        }
    }


# Protected endpoint example
@app.get("/api/v1/me", tags=["User"])
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return {
        "user": current_user.username,
        "roles": current_user.roles,
        "permissions": current_user.permissions
    }


# Include routers
app.include_router(
    assets_router,
    prefix="/api/v1/assets",
    tags=["Assets"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    alerts_router,
    prefix="/api/v1/alerts",
    tags=["Alerts"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    policies_router,
    prefix="/api/v1/policies",
    tags=["Policies"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    monitoring_router,
    prefix="/api/v1/monitoring",
    tags=["Monitoring"],
    dependencies=[Depends(get_current_user)]
)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """HTTP exception handler."""
    return {
        "error": True,
        "message": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.now().isoformat()
    }


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return {
        "error": True,
        "message": "Internal server error",
        "status_code": 500,
        "timestamp": datetime.now().isoformat()
    }


def main():
    """Run the API server."""
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
