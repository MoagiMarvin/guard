from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router as api_router
from core.database import init_db

app = FastAPI(
    title="Guard SOC Platform",
    description="AI-powered Security Operations Center for real-time threat detection.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialise the database and all tables on server start."""
    init_db()

# Include the API routes
app.include_router(api_router, prefix="/api", tags=["Guard SOC"])

@app.get("/")
async def root():
    return {
        "message": "Welcome to Guard SOC Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "operational",
        "agents": 13,
        "endpoints": "/api/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
