from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from api.routes import router as api_router
from core.database import init_db
from core.auth import require_api_key  # for testing

app = FastAPI(
    title="GUARD Security Platform",
    description="Enterprise-grade AI Security Operations Center.",
    version="1.2.0"
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

# Mount the static directory to serve CSS/JS (if needed)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include the API routes
app.include_router(api_router, prefix="/api", tags=["Guard SOC"])

@app.get("/")
async def root():
    """Serves the Premium Guard SOC Landing Page."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Guard SOC Active", "status": "operational"}

@app.get("/dashboard")
async def dashboard():
    """Serves the private SOC Dashboard."""
    dash_path = os.path.join(static_dir, "dashboard.html")
    if os.path.exists(dash_path):
        return FileResponse(dash_path)
    return {"error": "Dashboard file not found"}

@app.get("/join")
async def join():
    """Serves the Join/Signup page."""
    auth_path = os.path.join(static_dir, "auth.html")
    if os.path.exists(auth_path):
        return FileResponse(auth_path)
    return {"error": "Onboarding page not found"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
