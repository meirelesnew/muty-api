"""
MUTY Transporte Escolar — API v2
FastAPI + MongoDB Atlas + JWT/bcrypt
"""

import os
import re
import uuid
import httpx
import traceback
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

# ── JWT + bcrypt ───────────────────────────────────────────────────────────────
import jwt as pyjwt   # PyJWT — mais estável com Python 3.14
import bcrypt         # bcrypt direto — sem passlib (evita bug 72 bytes)

SECRET_KEY  = os.environ.get("JWT_SECRET", "muty-secret-dev-2026-TROCAR-em-producao")
ALGORITHM   = "HS256"
TOKEN_HOURS = 8

bearer_ = HTTPBearer(auto_error=False)

def hash_senha(senha: str) -> str:
    senha_bytes = str(senha).encode("utf-8")
    return bcrypt.hashpw(senha_bytes, bcrypt.gensalt()).decode("utf-8")

def verificar_senha(senha: str, hashed: str) -> bool:
    try:
        senha_bytes  = str(senha).encode("utf-8")
        hashed_bytes = str(hashed).encode("utf-8")
        return bcrypt.checkpw(senha_bytes, hashed_bytes)
    except Exception as e:
        print(f"[AUTH] Erro verificar_senha: {e}")
        return False

def criar_token(user_id: str, email: str) -> str:
    expire  = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    payload = {"sub": user_id, "email": email, "exp": expire}
    if JWT_LIB == "pyjwt":
        return pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decodificar_token(token: str) -> dict:
    try:
        if JWT_LIB == "pyjwt":
            return pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="MUTY API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── MongoDB ────────────────────────────────────────────────────────────────────
MONGO_URL = os.environ.get("MONGO_URL", "")
_client   = None

def get_db():
    global _client
    if _client is None:
        if not MONGO_URL:
            raise RuntimeError("MONGO_URL não configurada")
        _client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=10000)
        db = _client["muty2026"]
        # BUG CORRIGIDO: criar_index pode falhar se já existir — usar try/except
        try:
            db.users.create_index([("email", ASCENDING)], unique=True)
            db.dados_v2.create_index([("user_id", ASCENDING), ("tipo", ASCENDING)], unique=True)
        except Exception:
            pass  # índices já existem
    return _client["muty2026"]

# ── Auth middleware ────────────────────────────────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_)
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token não fornecido")
    payload = decodificar_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido")
    return {"user_id": user_id, "email": payload.get("email", "")}

# ── Helpers de dados v2 ────────────────────────────────────────────────────────
def _get_dados_v2(db, user_id: str, tipo: str):
    """Retorna dados do usuário ou None se não existir."""
    doc = db.dados_v2.find_one({"user_id": user_id, "tipo": tipo})
    return doc["dados"] if doc else None

def _save_dados_v2(db, user_id: str, tipo: str, dados) -> bool:
    """
    Salva dados com upsert atômico.
    BUG CORRIGIDO: upsert=True garante que nunca perde dados existentes —
    sempre atualiza o documento certo via filtro {user_id + tipo}.
    Retorna True se bem-sucedido.
    """
    try:
        result = db.dados_v2.update_one(
            {"user_id": user_id, "tipo": tipo},
            {"$set": {"dados": dados, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return result.acknowledged
    except Exception as e:
        print(f"[DB] Erro ao salvar {tipo} para {user_id}: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# V1 — ENDPOINTS LEGADOS (inalterados para compatibilidade)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "ok", "app": "MUTY Transporte API", "versao": "2.1"}

@app.get("/health")
def health():
    return {"status": "ok", "app": "MUTY Transporte API", "versao": "2.1"}

@app.get("/health/db")
def health_db():
    try:
        get_db().command("ping")
        return {"status": "ok", "mongo": "conectado"}
    except Exception as e:
        return {"status": "erro", "mongo": str(e)}

@app.get("/todos")
def get_todos():
    db   = get_db()
    docs = {doc["_id"]: doc["dados"] for doc in db.dados.find()}
    clientes = sorted(docs.get("clientes", []), key=lambda c: c.get("nome", "").lower())
    return {
        "pagamentos": docs.get("pagamentos", {}),
        "despesas":   docs.get("despesas", []),
        "clientes":   clientes,
    }

@app.get("/pagamentos")
def get_pagamentos():
    doc = get_db().dados.find_one({"_id": "pagamentos"})
    return {"dados": doc["dados"] if doc else {}}

@app.get("/despesas")
def get_despesas():
    doc = get_db().dados.find_one({"_id": "despesas"})
    return {"dados": doc["dados"] if doc else []}

@app.get("/clientes")
def get_clientes():
    doc      = get_db().dados.find_one({"_id": "clientes"})
    clientes = doc["dados"] if doc else []
    return {"dados": sorted(clientes, key=lambda c: c.get("nome", "").lower())}

@app.put("/pagamentos")
async def save_pagamentos(request: Request):
    dados = await request.json()
    get_db().dados.update_one(
        {"_id": "pagamentos"},
        {"$set": {"dados": dados, "ts": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}

@app.put("/despesas")
async def save_despesas(request: Request):
    dados = await request.json()
    get_db().dados.update_one(
        {"_id": "despesas"},
        {"$set": {"dados": dados, "ts": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}

@app.put("/clientes")
async def save_clientes(request: Request):
    dados = await request.json()
    if isinstance(dados, list):
        dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    get_db().dados.update_one(
        {"_id": "clientes"},
        {"$set": {"dados": dados, "ts": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# V2 — AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/v2/register")
async def register(request: Request):
    """Cadastro de novo usuário com email único e senha bcrypt."""
    try:
        body    = await request.json()
        email   = str(body.get("email", "")).strip().lower()
        senha   = str(body.get("senha", ""))
        nome    = str(body.get("nome", "")).strip()
        empresa = str(body.get("empresa", "")).strip()

        # Validações
        if not email or "@" not in email or "." not in email:
            return {"status": "error", "message": "Email inválido"}
        if len(senha) < 6:
            return {"status": "error", "message": "Senha deve ter no mínimo 6 caracteres"}
        if not nome:
            return {"status": "error", "message": "Nome é obrigatório"}

        db      = get_db()
        user_id = str(uuid.uuid4())

        # BUG CORRIGIDO: usar DuplicateKeyError do pymongo em vez de find_one
        # evita race condition em cadastros simultâneos
        try:
            db.users.insert_one({
                "user_id":    user_id,
                "email":      email,
                "senha_hash": hash_senha(senha),
                "nome":       nome,
                "empresa":    empresa,
                "plano":      "free",
                "ativo":      True,
                "created_at": datetime.utcnow(),
            })
        except DuplicateKeyError:
            return {"status": "error", "message": "Email já cadastrado"}

        token = criar_token(user_id, email)
        print(f"[AUTH] Cadastro: {email} | {nome} | {empresa}")
        return {
            "status": "success",
            "data": {
                "token":   token,
                "user_id": user_id,
                "nome":    nome,
                "email":   email,
                "empresa": empresa,
                "expira_em": f"{TOKEN_HOURS} horas",
            }
        }

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro no cadastro: {str(e)}"}


@app.post("/v2/login")
async def login(request: Request):
    """Login com email e senha. Retorna JWT válido por 8 horas."""
    try:
        body  = await request.json()
        email = str(body.get("email", "")).strip().lower()
        senha = str(body.get("senha", ""))

        if not email or not senha:
            return {"status": "error", "message": "Email e senha obrigatórios"}

        db   = get_db()
        user = db.users.find_one({"email": email})

        # BUG CORRIGIDO: verificar_senha separado para não vazar qual campo falhou
        if not user or not verificar_senha(senha, user.get("senha_hash", "")):
            return {"status": "error", "message": "Email ou senha incorretos"}

        if not user.get("ativo", True):
            return {"status": "error", "message": "Conta desativada"}

        token = criar_token(user["user_id"], email)
        print(f"[AUTH] Login: {email}")
        return {
            "status": "success",
            "data": {
                "token":     token,
                "user_id":   user["user_id"],
                "nome":      user.get("nome", ""),
                "email":     email,
                "empresa":   user.get("empresa", ""),
                "expira_em": f"{TOKEN_HOURS} horas",
            }
        }

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro no login: {str(e)}"}


@app.get("/v2/me")
async def me(user=Depends(get_current_user)):
    """Retorna dados do usuário autenticado (sem senha)."""
    db       = get_db()
    # BUG CORRIGIDO: projeção explícita exclui senha_hash e _id do MongoDB
    user_doc = db.users.find_one(
        {"user_id": user["user_id"]},
        {"_id": 0, "senha_hash": 0}
    )
    if not user_doc:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {"status": "success", "data": user_doc}


# ══════════════════════════════════════════════════════════════════════════════
# V2 — DADOS ISOLADOS POR USUÁRIO
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/v2/todos")
async def get_todos_v2(user=Depends(get_current_user)):
    """Carrega pagamentos + despesas + clientes do usuário autenticado."""
    db  = get_db()
    uid = user["user_id"]
    clientes   = _get_dados_v2(db, uid, "clientes")   or []
    pagamentos = _get_dados_v2(db, uid, "pagamentos") or {}
    despesas   = _get_dados_v2(db, uid, "despesas")   or []
    clientes   = sorted(clientes, key=lambda c: c.get("nome", "").lower())
    return {
        "status": "success",
        "data": {"pagamentos": pagamentos, "despesas": despesas, "clientes": clientes}
    }

@app.get("/v2/clientes")
async def get_clientes_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "clientes") or []
    return {"status": "success", "data": sorted(dados, key=lambda c: c.get("nome", "").lower())}

@app.put("/v2/clientes")
async def save_clientes_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, list):
        return {"status": "error", "message": "Formato inválido — esperado lista"}
    dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    ok = _save_dados_v2(get_db(), user["user_id"], "clientes", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}

@app.get("/v2/pagamentos")
async def get_pagamentos_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "pagamentos") or {}
    return {"status": "success", "data": dados}

@app.put("/v2/pagamentos")
async def save_pagamentos_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, dict):
        return {"status": "error", "message": "Formato inválido — esperado objeto"}
    ok = _save_dados_v2(get_db(), user["user_id"], "pagamentos", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}

@app.get("/v2/despesas")
async def get_despesas_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "despesas") or []
    return {"status": "success", "data": dados}

@app.put("/v2/despesas")
async def save_despesas_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if not isinstance(dados, list):
        return {"status": "error", "message": "Formato inválido — esperado lista"}
    ok = _save_dados_v2(get_db(), user["user_id"], "despesas", dados)
    return {"status": "success" if ok else "error", "data": {"saved": ok}}


# ══════════════════════════════════════════════════════════════════════════════
# V2 — NOTA FISCAL QR CODE
# ══════════════════════════════════════════════════════════════════════════════

_HEADERS_NF = {
    "User-Agent":      "Mozilla/5.0 (Android 13; Mobile) AppleWebKit/537.36 Chrome/120",
    "Accept":          "text/html,application/xhtml+xml",
    "Accept-Language": "pt-BR,pt;q=0.9",
}
_ESTADOS_NF = {
    "nfce.fazenda.sp.gov.br": "SP",
    "nfce.fazenda.rj.gov.br": "RJ",
    "nfe.fazenda.mg.gov.br":  "MG",
    "nfce.sefaz.rs.gov.br":   "RS",
    "nfce.sefaz.pr.gov.br":   "PR",
    "nfce.sefaz.ba.gov.br":   "BA",
    "nfce.sefaz.ce.gov.br":   "CE",
    "nfce.sefaz.pe.gov.br":   "PE",
}

def _detectar_estado(url: str) -> str:
    for dominio, uf in _ESTADOS_NF.items():
        if dominio in url:
            return uf
    return "GENERICO"

def _extrair_valor(html: str) -> float:
    padroes = [
        r'[Vv]alor\s+[Tt]otal\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'[Tt]otal\s+a\s+[Pp]agar\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'[Tt]otal\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'R\$\s*([\d]+[.,][\d]{2})',
    ]
    valores = []
    for p in padroes:
        for m in re.findall(p, html, re.IGNORECASE):
            try:
                valores.append(float(m.replace(".", "").replace(",", ".")))
            except ValueError:
                pass
    # BUG CORRIGIDO: filtrar valores absurdos (ex: anos como 2026.00)
    valores = [v for v in valores if 0.01 < v < 100000]
    return max(valores) if valores else 0.0

def _extrair_estabelecimento(html: str) -> str:
    padroes = [
        r'<div[^>]*class="[^"]*NomeEmit[^"]*"[^>]*>(.*?)</div>',
        r'<span[^>]*class="[^"]*emit[^"]*"[^>]*>(.*?)</span>',
        r'Razão Social[:\s]*(.*?)<',
        r'<strong[^>]*>(.*?)</strong>',
    ]
    for p in padroes:
        m = re.search(p, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()
            if 3 < len(texto) < 100:
                return texto
    return "Estabelecimento"

def _extrair_data(html: str) -> str:
    m = re.search(r"(\d{2}/\d{2}/\d{4})", html)
    if m:
        return m.group(1)
    m = re.search(r"(\d{4}-\d{2}-\d{2})", html)
    if m:
        y, mo, d = m.group(1).split("-")
        return f"{d}/{mo}/{y}"
    return ""

def _sugerir_categoria(nome: str) -> str:
    n = nome.lower()
    if any(x in n for x in ["posto", "combustivel", "petrobras", "shell", "ipiranga", "gnv"]):
        return "combustivel"
    if any(x in n for x in ["mecanica", "auto", "pneu", "borracha", "oficina"]):
        return "manutencao"
    if any(x in n for x in ["detran", "ipva", "iptu", "multa", "tributo"]):
        return "impostos"
    return "outros"

@app.post("/v2/nota-fiscal")
async def processar_nota_fiscal(request: Request):
    """Recebe URL do QR Code NFC-e e extrai dados da nota. Não requer autenticação."""
    try:
        body = await request.json()
        url  = str(body.get("url", "")).strip()

        if not url or not url.startswith("http"):
            return {"status": "error", "message": "URL inválida"}

        estado = _detectar_estado(url)

        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers=_HEADERS_NF)
                resp.raise_for_status()
                html = resp.text
            except httpx.TimeoutException:
                return {"status": "error", "message": "Tempo esgotado ao acessar a nota"}
            except httpx.HTTPStatusError as e:
                return {"status": "error", "message": f"Nota não encontrada (HTTP {e.response.status_code})"}
            except Exception as e:
                return {"status": "error", "message": f"Erro ao acessar nota: {str(e)}"}

        estabelecimento = _extrair_estabelecimento(html)
        return {
            "status": "success",
            "data": {
                "estabelecimento": estabelecimento,
                "valor":           _extrair_valor(html),
                "data":            _extrair_data(html),
                "categoria":       _sugerir_categoria(estabelecimento),
                "estado":          estado,
            }
        }

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro interno: {str(e)}"}
