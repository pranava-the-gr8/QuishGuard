from fastapi import FastAPI
from app.routes.scan import router as scan_router

app = FastAPI(
    title="Zero-Execution Inspection Engine",
    description="QR Code Phishing and Malicious URL Detection API",
    version="1.0.0"
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "Zero-Execution Inspection Engine"
    }


app.include_router(scan_router)