from datetime import datetime
from fastapi import APIRouter

# Create an APIRouter instance for health-related endpoints
router = APIRouter(tags=["Health"])

@router.get("/api/health")
def health_check():
    """Lightweight endpoint for uptime monitoring and keeping the service awake."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}