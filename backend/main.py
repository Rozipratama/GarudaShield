
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="GarudaShield API",
    description="Backend API for network security monitoring",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Data simulasi. Nantinya diganti dengan alert dari Wazuh.
demo_alerts = [
    {
        "id": 1,
        "timestamp": "2026-10-21T10:42:15Z",
        "source_ip": "192.168.56.20",
        "description": "GarudaShield syslog test",
        "severity": "low",
        "simulated": True,
    },
    {
        "id": 2,
        "timestamp": "2026-10-21T10:39:08Z",
        "source_ip": "192.168.56.20",
        "description": "Contoh peringatan sistem",
        "severity": "medium",
        "simulated": True,
    },
    {
        "id": 3,
        "timestamp": "2026-10-21T10:32:41Z",
        "source_ip": "192.168.56.20",
        "description": "Contoh kejadian berprioritas tinggi",
        "severity": "high",
        "simulated": True,
    },
]


@app.get("/")
def root():
    return {
        "application": "GarudaShield",
        "version": "0.1.0",
        "message": "API is running",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/alerts")
def get_alerts():
    return {
        "mode": "simulation",
        "total": len(demo_alerts),
        "alerts": demo_alerts,
    }


@app.get("/api/summary")
def get_summary():
    return {
        "mode": "simulation",
        "total_alerts": len(demo_alerts),
        "high_alerts": sum(
            alert["severity"] == "high"
            for alert in demo_alerts
        ),
        "source": "demo",
    }
