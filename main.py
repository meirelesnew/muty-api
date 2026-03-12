from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from pydantic import BaseModel
from typing import Any, Optional
import os
from datetime import datetime

app = FastAPI(title="MUTY Transporte API", version="1.0.0")

# CORS — permite o GitHub Pages chamar a API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção: ["https://meirelesnew.github.io"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Atlas — connection string via variável de ambiente
MONGO_URL = os.environ.get("MONGO_URL", "")
client = None
db = None

def get_db():
    global client, db
    if client is None:
        client = MongoClient(MONGO_URL)
        db = client["muty2026"]
    return db

# ── MODELS ──────────────────────────────────────────────────────────────────

class DadosRequest(BaseModel):
    dados: Any

# ── HEALTH CHECK ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "app": "MUTY Transporte API", "version": "1.0.0"}

@app.get("/health")
def health():
    try:
        get_db().command("ping")
        return {"status": "ok", "mongo": "conectado"}
    except Exception as e:
        return {"status": "erro", "mongo": str(e)}

# ── PAGAMENTOS ───────────────────────────────────────────────────────────────

@app.get("/pagamentos")
def get_pagamentos():
    db = get_db()
    doc = db.dados.find_one({"_id": "pagamentos"})
    return {"dados": doc["dados"] if doc else {}}

@app.put("/pagamentos")
def save_pagamentos(req: DadosRequest):
    db = get_db()
    db.dados.update_one(
        {"_id": "pagamentos"},
        {"$set": {"dados": req.dados, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}

# ── DESPESAS ─────────────────────────────────────────────────────────────────

@app.get("/despesas")
def get_despesas():
    db = get_db()
    doc = db.dados.find_one({"_id": "despesas"})
    return {"dados": doc["dados"] if doc else []}

@app.put("/despesas")
def save_despesas(req: DadosRequest):
    db = get_db()
    db.dados.update_one(
        {"_id": "despesas"},
        {"$set": {"dados": req.dados, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}

# ── CLIENTES ─────────────────────────────────────────────────────────────────

@app.get("/clientes")
def get_clientes():
    db = get_db()
    doc = db.dados.find_one({"_id": "clientes"})
    clientes = doc["dados"] if doc else []
    # Ordenar alfabeticamente
    clientes_sorted = sorted(clientes, key=lambda c: c.get("nome", "").lower())
    return {"dados": clientes_sorted}

@app.put("/clientes")
def save_clientes(req: DadosRequest):
    db = get_db()
    # Ordenar antes de salvar
    clientes = req.dados
    if isinstance(clientes, list):
        clientes = sorted(clientes, key=lambda c: c.get("nome", "").lower())
    db.dados.update_one(
        {"_id": "clientes"},
        {"$set": {"dados": clientes, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}

# ── TODOS OS DADOS DE UMA VEZ (carregamento inicial) ─────────────────────────

@app.get("/todos")
def get_todos():
    db = get_db()
    docs = {doc["_id"]: doc["dados"] for doc in db.dados.find()}
    clientes = docs.get("clientes", [])
    clientes_sorted = sorted(clientes, key=lambda c: c.get("nome", "").lower())
    return {
        "pagamentos": docs.get("pagamentos", {}),
        "despesas":   docs.get("despesas", []),
        "clientes":   clientes_sorted,
    }
