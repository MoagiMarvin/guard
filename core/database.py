"""
GUARD - Secure Database Layer
Handles permanent storage for Users, Clients, and Security Incidents.
Supports both Local SQLite (for development) and Supabase Postgres (for production).
"""
import os
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Choose engine based on environment
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fallback to local SQLite if no DATABASE_URL is provided
    DATABASE_URL = "sqlite:///./guard_soc.db"
    logger.warning("No DATABASE_URL found. Falling back to local SQLite.")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ==========================================
# DATABASE MODELS
# ==========================================

class User(Base):
    """Stores GUARD Dashboard users (the site owners/developers)."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship to protected sites
    clients = relationship("Client", back_populates="owner")

class Client(Base):
    """Stores protected site configurations and their API keys."""
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    site_name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    plan_type = Column(String, default="FREE")  # FREE, SENTINEL, ENTERPRISE
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="clients")

class Incident(Base):
    """Stores single security detections."""
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    client_id = Column(String, index=True, nullable=False) # Maps to API Key
    agent = Column(String, nullable=False)
    status = Column(String, nullable=False)
    threat_level = Column(String, nullable=False)
    payload = Column(Text)
    result = Column(JSON, nullable=False)

class PipelineRun(Base):
    """Stores full multi-agent SOC responses."""
    __tablename__ = "pipeline_runs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    client_id = Column(String, index=True, nullable=False)
    threat_type = Column(String, nullable=False)
    payload = Column(Text)
    detection = Column(JSON)
    ir_response = Column(JSON)
    threat_intel = Column(JSON)
    report = Column(JSON)
    deadman_fired = Column(Boolean, default=False)
    final_status = Column(String, nullable=False)


# ==========================================
# REPOSITORY FUNCTIONS (Database Access)
# ==========================================

def init_db():
    """Initialises the database tables."""
    Base.metadata.create_all(bind=engine)
    logger.info("GUARD Database initialised.")

def get_db():
    """Provides a session to FastAPI endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Sync wrappers for existing agent logic ---

def save_incident(client_id: str, agent: str, status: str, threat_level: str, payload: str, result: dict):
    db = SessionLocal()
    try:
        new_incident = Incident(
            client_id=client_id,
            agent=agent,
            status=status,
            threat_level=threat_level,
            payload=str(payload)[:2000],
            result=result
        )
        db.add(new_incident)
        db.commit()
        db.refresh(new_incident)
        return new_incident.id
    finally:
        db.close()

def save_pipeline_run(client_id, threat_type, payload, detection, ir_response=None, threat_intel=None, report=None, deadman_fired=False, final_status="COMPLETED"):
    db = SessionLocal()
    try:
        new_run = PipelineRun(
            client_id=client_id,
            threat_type=threat_type,
            payload=str(payload)[:2000],
            detection=detection,
            ir_response=ir_response,
            threat_intel=threat_intel,
            report=report,
            deadman_fired=deadman_fired,
            final_status=final_status
        )
        db.add(new_run)
        db.commit()
        db.refresh(new_run)
        return new_run.id
    finally:
        db.close()

def get_all_incidents(limit: int = 100, client_id: str = "Admin"):
    db = SessionLocal()
    try:
        query = db.query(Incident)
        if client_id != "Admin":
            query = query.filter(Incident.client_id == client_id)
        return [inc.__dict__ for inc in query.order_by(Incident.id.desc()).limit(limit).all()]
    finally:
        db.close()

def get_all_pipeline_runs(limit: int = 50, client_id: str = "Admin"):
    db = SessionLocal()
    try:
        query = db.query(PipelineRun)
        if client_id != "Admin":
            query = query.filter(PipelineRun.client_id == client_id)
        return [run.__dict__ for run in query.order_by(PipelineRun.id.desc()).limit(limit).all()]
    finally:
        db.close()

def get_incident_stats(client_id: str = "Admin"):
    db = SessionLocal()
    try:
        if client_id == "Admin":
            total = db.query(Incident).count()
            dangerous = db.query(Incident).filter(Incident.status == "DANGEROUS").count()
            critical = db.query(Incident).filter(Incident.threat_level == "CRITICAL").count()
            runs = db.query(PipelineRun).count()
            deadman = db.query(PipelineRun).filter(PipelineRun.deadman_fired == True).count()
        else:
            total = db.query(Incident).filter(Incident.client_id == client_id).count()
            dangerous = db.query(Incident).filter(Incident.client_id == client_id, Incident.status == "DANGEROUS").count()
            critical = db.query(Incident).filter(Incident.client_id == client_id, Incident.threat_level == "CRITICAL").count()
            runs = db.query(PipelineRun).filter(PipelineRun.client_id == client_id).count()
            deadman = db.query(PipelineRun).filter(Incident.client_id == client_id, PipelineRun.deadman_fired == True).count()

        return {
            "identity": client_id,
            "total_incidents": total,
            "dangerous_incidents": dangerous,
            "critical_incidents": critical,
            "total_pipeline_runs": runs,
            "deadman_activations": deadman
        }
    finally:
        db.close()
