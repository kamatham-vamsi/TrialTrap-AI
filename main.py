from fastapi import FastAPI
from pydantic import BaseModel
from datetime import date, datetime
import sqlite3
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="TrialTrap AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {
        "message": "TrialTrap AI is running!",
        "status": "success"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}