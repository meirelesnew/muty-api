from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from typing import Any
import os
from datetime import datetime

app = FastAPI(title="MUTY Transporte API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URL = os.environ.get("MONGO_URL", "")
_client = None

def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URL)
    return _client["muty2026"]

@app.get("/")
def root():
    return {"status": "ok", "app": "MUTY Transporte API"}

@app.get("/health")
def health():
    try:
        get_db().command("ping")
        return {"status": "ok", "mongo": "conectado"}
    except Exception as e:
        return {"status": "erro", "mongo": str(e)}

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

@app.get("/pagamentos")
def get_pagamentos():
    db = get_db()
    doc = db.dados.find_one({"_id": "pagamentos"})
    return {"dados": doc["dados"] if doc else {}}

@app.get("/despesas")
def get_despesas():
    db = get_db()
    doc = db.dados.find_one({"_id": "despesas"})
    return {"dados": doc["dados"] if doc else []}

@app.get("/clientes")
def get_clientes():
    db = get_db()
    doc = db.dados.find_one({"_id": "clientes"})
    clientes = doc["dados"] if doc else []
    return {"dados": sorted(clientes, key=lambda c: c.get("nome", "").lower())}

@app.put("/pagamentos")
async def save_pagamentos(request: Request):
    dados = await request.json()
    db = get_db()
    db.dados.update_one({"_id": "pagamentos"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}

@app.put("/despesas")
async def save_despesas(request: Request):
    dados = await request.json()
    db = get_db()
    db.dados.update_one({"_id": "despesas"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}

@app.put("/clientes")
async def save_clientes(request: Request):
    dados = await request.json()
    db = get_db()
    if isinstance(dados, list):
        dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    db.dados.update_one({"_id": "clientes"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}
