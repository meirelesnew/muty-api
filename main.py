from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient, ASCENDING
from datetime import datetime, timedelta
from typing import Optional
import os, uuid, httpx, re

# ── JWT + bcrypt ──────────────────────────────────────────────────────────────
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY  = os.environ.get("JWT_SECRET", "muty-secret-dev-2026-trocar-em-producao")
ALGORITHM   = "HS256"
TOKEN_HOURS = 8

pwd_ctx    = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_    = HTTPBearer(auto_error=False)

def hash_senha(senha: str) -> str:
    return pwd_ctx.hash(senha)

def verificar_senha(senha: str, hashed: str) -> bool:
    return pwd_ctx.verify(senha, hashed)

def criar_token(user_id: str, email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": user_id, "email": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def decodificar_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="MUTY API v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── MongoDB ───────────────────────────────────────────────────────────────────
MONGO_URL = os.environ.get("MONGO_URL", "")
_client   = None

def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URL)
        # Índices para performance com múltiplos usuários
        db = _client["muty2026"]
        db.users.create_index([("email", ASCENDING)], unique=True)
        db.dados_v2.create_index([("user_id", ASCENDING), ("tipo", ASCENDING)])
    return _client["muty2026"]

# ── Middleware de autenticação ─────────────────────────────────────────────────
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token não fornecido")
    payload = decodificar_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido")
    return {"user_id": user_id, "email": payload.get("email")}

# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS V1 — INALTERADOS (compatibilidade total)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "ok", "app": "MUTY Transporte API", "versao": "2.0"}

@app.get("/health")
def health():
    return {"status": "ok", "app": "MUTY Transporte API"}

@app.get("/health/db")
def health_db():
    try:
        get_db().command("ping")
        return {"status": "ok", "mongo": "conectado"}
    except Exception as e:
        return {"status": "erro", "mongo": str(e)}

@app.get("/todos")
def get_todos():
    db  = get_db()
    docs = {doc["_id"]: doc["dados"] for doc in db.dados.find()}
    clientes = sorted(docs.get("clientes", []), key=lambda c: c.get("nome", "").lower())
    return {"pagamentos": docs.get("pagamentos", {}), "despesas": docs.get("despesas", []), "clientes": clientes}

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
    doc = get_db().dados.find_one({"_id": "clientes"})
    clientes = doc["dados"] if doc else []
    return {"dados": sorted(clientes, key=lambda c: c.get("nome", "").lower())}

@app.put("/pagamentos")
async def save_pagamentos(request: Request):
    dados = await request.json()
    get_db().dados.update_one({"_id": "pagamentos"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}

@app.put("/despesas")
async def save_despesas(request: Request):
    dados = await request.json()
    get_db().dados.update_one({"_id": "despesas"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}

@app.put("/clientes")
async def save_clientes(request: Request):
    dados = await request.json()
    if isinstance(dados, list):
        dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    get_db().dados.update_one({"_id": "clientes"}, {"$set": {"dados": dados, "ts": datetime.utcnow()}}, upsert=True)
    return {"ok": True}

# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS V2 — AUTENTICAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/v2/register")
async def register(request: Request):
    """Cadastro de novo usuário. Email único obrigatório."""
    try:
        body  = await request.json()
        email = body.get("email", "").strip().lower()
        senha = body.get("senha", "")
        nome  = body.get("nome", "").strip()
        empresa = body.get("empresa", "").strip()

        # Validações
        if not email or "@" not in email:
            return {"status": "error", "message": "Email inválido"}
        if len(senha) < 6:
            return {"status": "error", "message": "Senha deve ter no mínimo 6 caracteres"}
        if not nome:
            return {"status": "error", "message": "Nome é obrigatório"}

        db = get_db()

        # Verificar email único
        if db.users.find_one({"email": email}):
            return {"status": "error", "message": "Email já cadastrado"}

        # Criar usuário
        user_id = str(uuid.uuid4())
        db.users.insert_one({
            "user_id":    user_id,
            "email":      email,
            "senha_hash": hash_senha(senha),
            "nome":       nome,
            "empresa":    empresa,
            "plano":      "free",
            "created_at": datetime.utcnow(),
        })

        token = criar_token(user_id, email)
        print(f"[AUTH] Novo usuário: {email} | {nome} | {empresa}")
        return {
            "status": "success",
            "data": {"token": token, "user_id": user_id, "nome": nome, "email": email, "empresa": empresa}
        }

    except Exception as e:
        print(f"[AUTH] Erro register: {e}")
        import traceback; traceback.print_exc()
        return {"status": "error", "message": f"Erro interno: {str(e)}"}


@app.post("/v2/login")
async def login(request: Request):
    """Login com email e senha. Retorna JWT válido por 8 horas."""
    try:
        body  = await request.json()
        email = body.get("email", "").strip().lower()
        senha = body.get("senha", "")

        if not email or not senha:
            return {"status": "error", "message": "Email e senha obrigatórios"}

        db   = get_db()
        user = db.users.find_one({"email": email})

        if not user or not verificar_senha(senha, user["senha_hash"]):
            return {"status": "error", "message": "Email ou senha incorretos"}

        token = criar_token(user["user_id"], email)
        print(f"[AUTH] Login: {email}")
        return {
            "status": "success",
            "data": {
                "token":   token,
                "user_id": user["user_id"],
                "nome":    user.get("nome", ""),
                "email":   email,
                "empresa": user.get("empresa", ""),
                "expira_em": f"{TOKEN_HOURS} horas"
            }
        }

    except Exception as e:
        print(f"[AUTH] Erro login: {e}")
        import traceback; traceback.print_exc()
        return {"status": "error", "message": f"Erro interno: {str(e)}"}


@app.get("/v2/me")
async def me(user=Depends(get_current_user)):
    """Retorna dados do usuário autenticado."""
    db   = get_db()
    user_doc = db.users.find_one({"user_id": user["user_id"]}, {"senha_hash": 0, "_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {"status": "success", "data": user_doc}


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS V2 — DADOS ISOLADOS POR USUÁRIO
# ═══════════════════════════════════════════════════════════════════════════════

def _get_dados_v2(db, user_id: str, tipo: str):
    doc = db.dados_v2.find_one({"user_id": user_id, "tipo": tipo})
    return doc["dados"] if doc else None

def _save_dados_v2(db, user_id: str, tipo: str, dados):
    db.dados_v2.update_one(
        {"user_id": user_id, "tipo": tipo},
        {"$set": {"dados": dados, "updated_at": datetime.utcnow()}},
        upsert=True
    )

@app.get("/v2/todos")
async def get_todos_v2(user=Depends(get_current_user)):
    """Carrega todos os dados do usuário autenticado de uma vez."""
    db      = get_db()
    uid     = user["user_id"]
    clientes    = _get_dados_v2(db, uid, "clientes") or []
    pagamentos  = _get_dados_v2(db, uid, "pagamentos") or {}
    despesas    = _get_dados_v2(db, uid, "despesas") or []
    clientes    = sorted(clientes, key=lambda c: c.get("nome", "").lower())
    return {"status": "success", "data": {"pagamentos": pagamentos, "despesas": despesas, "clientes": clientes}}

@app.get("/v2/clientes")
async def get_clientes_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "clientes") or []
    return {"status": "success", "data": sorted(dados, key=lambda c: c.get("nome", "").lower())}

@app.put("/v2/clientes")
async def save_clientes_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    if isinstance(dados, list):
        dados = sorted(dados, key=lambda c: c.get("nome", "").lower())
    _save_dados_v2(get_db(), user["user_id"], "clientes", dados)
    return {"status": "success", "data": {"ok": True}}

@app.get("/v2/pagamentos")
async def get_pagamentos_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "pagamentos") or {}
    return {"status": "success", "data": dados}

@app.put("/v2/pagamentos")
async def save_pagamentos_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    _save_dados_v2(get_db(), user["user_id"], "pagamentos", dados)
    return {"status": "success", "data": {"ok": True}}

@app.get("/v2/despesas")
async def get_despesas_v2(user=Depends(get_current_user)):
    dados = _get_dados_v2(get_db(), user["user_id"], "despesas") or []
    return {"status": "success", "data": dados}

@app.put("/v2/despesas")
async def save_despesas_v2(request: Request, user=Depends(get_current_user)):
    dados = await request.json()
    _save_dados_v2(get_db(), user["user_id"], "despesas", dados)
    return {"status": "success", "data": {"ok": True}}


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT V2 — NOTA FISCAL QR CODE (inalterado)
# ═══════════════════════════════════════════════════════════════════════════════

HEADERS_NF = {
    "User-Agent": "Mozilla/5.0 (Android 13; Mobile) AppleWebKit/537.36 Chrome/120",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "pt-BR,pt;q=0.9",
}

def detectar_estado(url):
    mapa = {"nfce.fazenda.sp.gov.br":"SP","nfce.fazenda.rj.gov.br":"RJ",
            "nfe.fazenda.mg.gov.br":"MG","nfce.sefaz.rs.gov.br":"RS",
            "nfce.sefaz.pr.gov.br":"PR","nfce.sefaz.ba.gov.br":"BA"}
    for d, uf in mapa.items():
        if d in url: return uf
    return "GENERICO"

def extrair_valor(html):
    padroes = [
        r'[Vv]alor\s+[Tt]otal\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'[Tt]otal\s+a\s+[Pp]agar\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'[Tt]otal\s*[:\-]?\s*R?\$?\s*([\d]+[.,][\d]{2})',
        r'R\$\s*([\d]+[.,][\d]{2})',
    ]
    for p in padroes:
        matches = re.findall(p, html, re.IGNORECASE)
        if matches:
            valores = []
            for m in matches:
                try: valores.append(float(m.replace('.','').replace(',','.')))
                except: pass
            if valores: return max(valores)
    return 0.0

def extrair_estabelecimento(html, estado):
    padroes = [
        r'<div[^>]*class="[^"]*NomeEmit[^"]*"[^>]*>(.*?)</div>',
        r'<span[^>]*class="[^"]*emit[^"]*"[^>]*>(.*?)</span>',
        r'Razão Social[:\s]*(.*?)<',
        r'<strong[^>]*>(.*?)</strong>',
    ]
    for p in padroes:
        m = re.search(p, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', m.group(1))).strip()
            if 3 < len(texto) < 100: return texto
    return "Estabelecimento"

def extrair_data(html):
    m = re.search(r'(\d{2}/\d{2}/\d{4})', html)
    if m: return m.group(1)
    m = re.search(r'(\d{4}-\d{2}-\d{2})', html)
    if m:
        p = m.group(1).split('-')
        return f"{p[2]}/{p[1]}/{p[0]}"
    return ""

def sugerir_categoria(nome):
    n = nome.lower()
    if any(x in n for x in ['posto','combustivel','petrobras','shell','ipiranga','gnv']): return 'combustivel'
    if any(x in n for x in ['mecanica','auto','pneu','borracha','oficina']): return 'manutencao'
    if any(x in n for x in ['detran','ipva','iptu','multa','tributo']): return 'impostos'
    return 'outros'

@app.post("/v2/nota-fiscal")
async def processar_nota_fiscal(request: Request):
    try:
        body = await request.json()
        url  = body.get("url", "").strip()
        if not url or not url.startswith("http"):
            return {"status": "error", "message": "URL inválida"}
        estado = detectar_estado(url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers=HEADERS_NF)
                resp.raise_for_status()
                html = resp.text
            except httpx.TimeoutException:
                return {"status": "error", "message": "Tempo esgotado ao acessar a nota"}
            except httpx.HTTPStatusError as e:
                return {"status": "error", "message": f"Nota não encontrada (HTTP {e.response.status_code})"}
            except Exception as e:
                return {"status": "error", "message": f"Erro ao acessar nota: {str(e)}"}
        valor           = extrair_valor(html)
        estabelecimento = extrair_estabelecimento(html, estado)
        data            = extrair_data(html)
        categoria       = sugerir_categoria(estabelecimento)
        return {"status": "success", "data": {
            "estabelecimento": estabelecimento, "valor": valor,
            "data": data, "categoria": categoria, "estado": estado
        }}
    except Exception as e:
        return {"status": "error", "message": "Erro interno"}
