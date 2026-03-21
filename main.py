"""
MUTY Transporte Escolar — API v2
FastAPI + MongoDB Atlas + JWT/bcrypt
"""

import os
import re
import uuid
import httpx
import traceback
import secrets
import base64
import json
from datetime import datetime, timedelta

import resend
from email_validator import validate_email, EmailNotValidError

from fastapi import FastAPI, Request, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

# ── JWT + bcrypt ───────────────────────────────────────────────────────────────
import jwt as pyjwt   # PyJWT — mais estável com Python 3.14
import bcrypt         # bcrypt direto — sem passlib (evita bug 72 bytes)

SECRET_KEY      = os.environ.get("JWT_SECRET",    "muty-secret-dev-2026-TROCAR-em-producao")
RESEND_API_KEY  = os.environ.get("RESEND_API_KEY", "")
GEMINI_API_KEY  = os.environ.get("GEMINI_API_KEY", "")   # NUNCA expor no frontend
FRONTEND_URL    = os.environ.get("FRONTEND_URL",   "https://meirelesnew.github.io/muty-transporte-2026")
ALGORITHM       = "HS256"
TOKEN_HOURS     = 8
VERIFY_HOURS    = 24  # token de verificação de email expira em 24h

resend.api_key = RESEND_API_KEY

bearer_ = HTTPBearer(auto_error=False)

# ── Validação de email ─────────────────────────────────────────────────────────
def validar_email(email: str) -> tuple[bool, str]:
    """
    Valida formato e domínio do email.
    Retorna (True, email_normalizado) ou (False, mensagem_erro)
    """
    try:
        info = validate_email(email, check_deliverability=False)
        return True, info.normalized
    except EmailNotValidError as e:
        return False, str(e)

# ── Validação de senha forte ───────────────────────────────────────────────────
def validar_senha(senha: str) -> tuple[bool, str]:
    """
    Valida requisitos de senha forte.
    Retorna (True, "") ou (False, mensagem_de_erro)
    """
    if len(senha) < 6:
        return False, "Senha deve ter no mínimo 6 caracteres"
    if not re.search(r'[A-Z]', senha):
        return False, "Senha deve ter pelo menos 1 letra maiúscula"
    if not re.search(r'[a-z]', senha):
        return False, "Senha deve ter pelo menos 1 letra minúscula"
    if not re.search(r'\d', senha):
        return False, "Senha deve ter pelo menos 1 número"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\];\'`~/\\]', senha):
        return False, "Senha deve ter pelo menos 1 caractere especial (!@#$%...)"
    return True, ""

# ── Envio de email via Resend ──────────────────────────────────────────────────
def _html_email(titulo: str, nome: str, mensagem: str, link: str, btn_texto: str) -> str:
    """Template HTML reutilizável para emails."""
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;
                background:#0a0e17;color:#e2e8f0;padding:32px;border-radius:16px;">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="font-size:48px;">🚌</div>
        <h1 style="font-family:Impact,sans-serif;letter-spacing:2px;
                   color:#f59e0b;margin:8px 0;">MUTY TRANSPORTE</h1>
      </div>
      <h2 style="color:#e2e8f0;font-size:18px;">{titulo}</h2>
      <p style="color:#94a3b8;line-height:1.6;">{mensagem}</p>
      <div style="text-align:center;margin:32px 0;">
        <a href="{link}"
           style="background:#f59e0b;color:#000;padding:14px 32px;
                  border-radius:10px;text-decoration:none;
                  font-weight:bold;font-size:16px;letter-spacing:1px;">
          {btn_texto}
        </a>
      </div>
      <p style="color:#475569;font-size:12px;margin-top:8px;">
        Ou copie o link: <a href="{link}" style="color:#60a5fa;">{link}</a>
      </p>
      <p style="color:#64748b;font-size:11px;text-align:center;margin-top:24px;">
        Este link expira em 24 horas. Se você não solicitou isso, ignore este email.
      </p>
    </div>
    """

def _enviar_email(para: str, assunto: str, html: str) -> tuple[bool, str]:
    """
    Envia email via Resend.com.
    Retorna (True, "") se ok ou (False, erro) se falhou.
    """
    if not RESEND_API_KEY:
        print(f"[EMAIL-DEV] RESEND_API_KEY não configurada")
        print(f"[EMAIL-DEV] Para: {para} | Assunto: {assunto}")
        return False, "RESEND_API_KEY não configurada no Render"

    try:
        resend.api_key = RESEND_API_KEY
        params: resend.Emails.SendParams = {
            "from":    "MUTY Transporte <onboarding@resend.dev>",
            "to":      [para],
            "subject": assunto,
            "html":    html,
        }
        resultado = resend.Emails.send(params)
        print(f"[EMAIL] Enviado para {para} | id={resultado.get('id','?')}")
        return True, ""
    except Exception as e:
        erro = str(e)
        print(f"[EMAIL] ERRO ao enviar para {para}: {erro}")
        traceback.print_exc()
        return False, erro

def enviar_email_verificacao(email: str, nome: str, token: str) -> bool:
    link = f"https://muty-api.onrender.com/v2/verify-email?token={token}"
    html = _html_email(
        titulo   = f"Olá, {nome}! 👋 Confirme seu cadastro",
        nome     = nome,
        mensagem = "Seu cadastro foi criado com sucesso. Clique no botão abaixo para confirmar seu email e ativar sua conta.",
        link     = link,
        btn_texto= "✅ CONFIRMAR EMAIL"
    )
    ok, _ = _enviar_email(email, "✅ Confirme seu cadastro — MUTY Transporte", html)
    return ok

def enviar_email_reset_senha(email: str, nome: str, token: str) -> bool:
    link = f"{FRONTEND_URL}?reset_token={token}"
    html = _html_email(
        titulo   = f"Olá, {nome}! Redefinição de senha",
        nome     = nome,
        mensagem = "Recebemos uma solicitação para redefinir a senha da sua conta. Clique no botão abaixo para criar uma nova senha.",
        link     = link,
        btn_texto= "🔑 REDEFINIR SENHA"
    )
    ok, _ = _enviar_email(email, "🔑 Redefinir senha — MUTY Transporte", html)
    return ok

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
    return pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decodificar_token(token: str) -> dict:
    try:
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
    return {"status": "ok", "app": "MUTY Transporte API", "versao": "2.2", "build": "20260321-0209"}

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
    """
    Cadastro de novo usuário.
    Valida email, senha forte, cria conta e envia email de verificação.
    """
    try:
        body    = await request.json()
        email   = str(body.get("email", "")).strip()
        senha   = str(body.get("senha", ""))
        nome    = str(body.get("nome", "")).strip()
        empresa = str(body.get("empresa", "")).strip()

        # ── Validar nome ──────────────────────────────────────────────────────
        if not nome:
            return {"status": "error", "message": "Nome é obrigatório"}

        # ── Validar email com biblioteca ──────────────────────────────────────
        ok_email, resultado_email = validar_email(email)
        if not ok_email:
            return {"status": "error", "message": f"Email inválido: {resultado_email}"}
        email = resultado_email  # usa email normalizado (lowercase, sem espaços)

        # ── Validar senha forte ───────────────────────────────────────────────
        ok_senha, msg_senha = validar_senha(senha)
        if not ok_senha:
            return {"status": "error", "message": msg_senha}

        db      = get_db()
        user_id = str(uuid.uuid4())

        # ── Token de verificação de email ─────────────────────────────────────
        verify_token   = secrets.token_urlsafe(32)  # token seguro aleatório
        verify_expira  = datetime.utcnow() + timedelta(hours=VERIFY_HOURS)

        # ── Criar usuário no MongoDB ──────────────────────────────────────────
        try:
            db.users.insert_one({
                "user_id":          user_id,
                "email":            email,
                "senha_hash":       hash_senha(senha),
                "nome":             nome,
                "empresa":          empresa,
                "plano":            "free",
                "ativo":            True,
                "is_verified":      False,          # conta não verificada ainda
                "verify_token":     verify_token,   # token do link de verificação
                "verify_expira":    verify_expira,  # expiração do token
                "created_at":       datetime.utcnow(),
            })
        except DuplicateKeyError:
            return {"status": "error", "message": "Email já cadastrado"}

        # ── Enviar email de verificação ───────────────────────────────────────
        email_enviado = enviar_email_verificacao(email, nome, verify_token)

        print(f"[AUTH] Cadastro: {email} | {nome} | email_enviado={email_enviado}")
        return {
            "status": "success",
            "data": {
                "user_id":       user_id,
                "nome":          nome,
                "email":         email,
                "empresa":       empresa,
                "is_verified":   False,
                "email_enviado": email_enviado,
                "mensagem":      "Cadastro criado! Verifique seu email para ativar a conta.",
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

        # Bloquear login se email não foi verificado
        if not user.get("is_verified", True):  # True = compatibilidade com contas antigas
            return {
                "status": "error",
                "message": "Verifique seu email antes de fazer login. Reenviar verificação em /v2/resend-verify",
                "code": "email_not_verified"
            }

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


@app.put("/v2/me")
async def atualizar_perfil(request: Request, user=Depends(get_current_user)):
    """Atualiza perfil do usuário: nickname, foto, telefone, empresa, nome."""
    try:
        body = await request.json()
        db   = get_db()

        campos_permitidos = {"nickname", "foto_url", "telefone", "empresa", "nome"}
        update = {}
        for campo in campos_permitidos:
            if campo in body and body[campo] is not None:
                valor = str(body[campo]).strip()
                if campo == "foto_url" and len(valor) > 500:
                    return {"status": "error", "message": "URL da foto muito longa"}
                if campo == "telefone":
                    valor = re.sub(r"[^\d\+\(\)\-\s]", "", valor)[:20]
                if campo == "nickname":
                    valor = valor[:30]
                if campo == "nome":
                    valor = valor[:80]
                if campo == "empresa":
                    valor = valor[:80]
                update[campo] = valor

        if not update:
            return {"status": "error", "message": "Nenhum campo para atualizar"}

        update["updated_at"] = datetime.utcnow()
        db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": update}
        )

        user_doc = db.users.find_one(
            {"user_id": user["user_id"]},
            {"_id": 0, "senha_hash": 0}
        )
        print(f"[PERFIL] Atualizado: {user['email']} | campos: {list(update.keys())}")
        return {"status": "success", "data": user_doc}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


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
# V2 — VERIFICAÇÃO DE EMAIL
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/v2/verify-email")
async def verify_email(token: str):
    """
    Ativação de conta via link do email.
    Usuário clica no link → conta é ativada → pode fazer login.
    """
    if not token:
        return {"status": "error", "message": "Token não fornecido"}

    db   = get_db()
    user = db.users.find_one({"verify_token": token})

    if not user:
        return {"status": "error", "message": "Link de verificação inválido ou já utilizado"}

    # Verificar expiração do token
    if datetime.utcnow() > user.get("verify_expira", datetime.utcnow()):
        # Token expirado — remover do banco mas manter conta
        db.users.update_one(
            {"verify_token": token},
            {"$unset": {"verify_token": "", "verify_expira": ""}}
        )
        return {
            "status": "error",
            "message": "Link expirado. Solicite um novo em /v2/resend-verify"
        }

    # Ativar conta — remover token e marcar como verificado
    db.users.update_one(
        {"verify_token": token},
        {"$set":   {"is_verified": True, "verified_at": datetime.utcnow()},
         "$unset": {"verify_token": "", "verify_expira": ""}}
    )

    print(f"[AUTH] Conta verificada: {user['email']}")

    # Retornar HTML amigável (usuário vê isso no navegador ao clicar no link)
    from fastapi.responses import HTMLResponse
    html = f"""<!DOCTYPE html>
    <html><head><meta charset="UTF-8">
    <meta http-equiv="refresh" content="4;url=https://meirelesnew.github.io/muty-transporte-2026">
    <title>Conta Verificada</title>
    <style>body{{font-family:Arial;background:#0a0e17;color:#e2e8f0;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
    .box{{background:#111827;border:1px solid #1f2d42;border-radius:16px;
      padding:40px;text-align:center;max-width:400px;}}
    h1{{color:#10b981;font-size:2rem;}} p{{color:#94a3b8;}}
    a{{color:#f59e0b;}} </style></head>
    <body><div class="box">
      <div style="font-size:4rem">✅</div>
      <h1>Conta Verificada!</h1>
      <p>Olá, <strong style="color:#e2e8f0">{user.get("nome","")}</strong>!</p>
      <p>Sua conta foi ativada com sucesso.<br>
         Você será redirecionado para o dashboard em instantes.</p>
      <p><a href="https://meirelesnew.github.io/muty-transporte-2026">
         Clique aqui se não for redirecionado</a></p>
    </div></body></html>"""
    return HTMLResponse(content=html)


@app.post("/v2/resend-verify")
async def resend_verify(request: Request):
    """
    Reenviar email de verificação para contas não verificadas.
    Útil quando o link expirou.
    """
    try:
        body  = await request.json()
        email = str(body.get("email", "")).strip().lower()

        if not email:
            return {"status": "error", "message": "Email obrigatório"}

        db   = get_db()
        user = db.users.find_one({"email": email})

        # Segurança: não revelar se email existe ou não
        if not user:
            return {"status": "success", "message": "Se o email existir, você receberá um novo link."}

        if user.get("is_verified"):
            return {"status": "error", "message": "Esta conta já está verificada"}

        # Gerar novo token
        new_token  = secrets.token_urlsafe(32)
        new_expira = datetime.utcnow() + timedelta(hours=VERIFY_HOURS)

        db.users.update_one(
            {"email": email},
            {"$set": {"verify_token": new_token, "verify_expira": new_expira}}
        )

        enviar_email_verificacao(email, user.get("nome", ""), new_token)
        return {"status": "success", "message": "Novo link de verificação enviado para seu email."}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}




# ══════════════════════════════════════════════════════════════════════════════
# V2 — OCR SEGURO VIA GEMINI (chave nunca exposta ao frontend)
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# OCR PIPELINE — QR → Gemini → Regex
# ══════════════════════════════════════════════════════════════════════════════

import re as _re
from urllib.parse import urlparse, parse_qs as _parse_qs

GEMINI_OCR_URL = (
    "https://generativelanguage.googleapis.com/v1beta"
    "/models/gemini-2.0-flash:generateContent"
)

PROMPT_OCR = (
    "Analise este cupom fiscal brasileiro e retorne APENAS JSON puro, "
    "sem markdown, sem explicação:\n"
    '{"estabelecimento":"string ou null",'
    '"valor_total":number ou null,'
    '"data":"YYYY-MM-DD ou null"}\n'
    "Regras: valor_total = TOTAL FINAL (ignorar subtotais e itens individuais). "
    "Converter vírgula para ponto: 45,90→45.90. "
    "Data em ISO: 23/03/2026→2026-03-23. "
    "Retornar null para campos não encontrados."
)

# ── Normalização ──────────────────────────────────────────────────────────────

def _norm_valor(v) -> float | None:
    if v is None:
        return None
    try:
        s = str(v).replace("R$", "").replace(" ", "").strip()
        # 1.234,56 → 1234.56
        if _re.match(r"^\d{1,3}(\.\d{3})+,\d{2}$", s):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", ".")
        f = float(s)
        return round(f, 2) if 0.01 < f < 100_000 else None
    except Exception:
        return None

def _norm_data(s) -> str | None:
    s = str(s or "").strip()
    if not s or s == "None":
        return None
    m = _re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = _re.match(r"(\d{2})[/\-](\d{2})[/\-](\d{4})", s)
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    return None

def _sugerir_cat(nome: str) -> str:
    n = (nome or "").lower()
    if any(x in n for x in ["posto", "gnv", "combusti", "gasolina", "etanol",
                              "ipiranga", "shell", "petrobras"]):
        return "combustivel"
    if any(x in n for x in ["mecanica", "auto ", "pneu", "borracha",
                              "oficina", "manutencao"]):
        return "manutencao"
    if any(x in n for x in ["detran", "ipva", "iptu", "multa", "tributo"]):
        return "impostos"
    return "outros"

# ── Fonte 1: QR Code ──────────────────────────────────────────────────────────

def _qr_extrair(url: str) -> dict:
    """Extrai vNF/dEmi/xNome diretamente da URL sem depender da SEFAZ."""
    r = {"estabelecimento": None, "valor_total": None, "data": None}
    if not url or not url.startswith("http"):
        return r
    try:
        params = _parse_qs(urlparse(url).query)
        for k in ["vNF", "vnf", "vNf", "vTotNF"]:
            if k in params:
                v = _norm_valor(params[k][0])
                if v:
                    r["valor_total"] = v
                    break
        for k in ["dEmi", "demi", "dhEmi"]:
            if k in params:
                d = _norm_data(params[k][0])
                if d:
                    r["data"] = d
                    break
        for k in ["xNome", "xnome", "razaoSocial"]:
            if k in params:
                nome = params[k][0]
                if len(nome) > 2:
                    r["estabelecimento"] = nome
                    break
        print(f"[QR] {r}")
    except Exception as e:
        print(f"[QR] erro: {e}")
    return r

# ── Fonte 2: Gemini ───────────────────────────────────────────────────────────

async def _gemini_ocr(b64: str, mime: str, key: str) -> tuple[dict, str]:
    """
    Gemini 1.5-flash, temp=0, timeout=30s.
    Envia payload como bytes (evita serialização JSON de imagens grandes).
    Retorna (dados, texto_bruto).
    """
    vazio = {"estabelecimento": None, "valor_total": None, "data": None}
    texto = ""

    if not key:
        print("[GEMINI] sem chave — pulando")
        return vazio, ""

    b64_kb = len(b64) // 1024
    print(f"[GEMINI] iniciando | imagem: {b64_kb}KB b64 | mime: {mime}")

    try:
        payload = {
            "contents": [{
                "parts": [
                    {"inline_data": {"mime_type": mime, "data": b64}},
                    {"text": PROMPT_OCR}
                ]
            }],
            "generationConfig": {
                "temperature":      0,
                "responseMimeType": "application/json",
            }
        }

        # Serializar manualmente para bytes — evita problema com payloads grandes
        import json as _json
        payload_bytes = _json.dumps(payload).encode("utf-8")
        print(f"[GEMINI] payload serializado: {len(payload_bytes)//1024}KB")

        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as cli:
            resp = await cli.post(
                f"{GEMINI_OCR_URL}?key={key}",
                content=payload_bytes,
                headers={"Content-Type": "application/json"}
            )

        print(f"[GEMINI] HTTP {resp.status_code}")

        if not resp.is_success:
            body_preview = resp.text[:200]
            print(f"[GEMINI] erro body: {body_preview}")
            return vazio, ""

        resp_json = resp.json()
        texto = (resp_json
                 .get("candidates", [{}])[0]
                 .get("content", {})
                 .get("parts", [{}])[0]
                 .get("text", ""))

        print(f"[GEMINI] texto recebido: {len(texto)} chars | preview: {texto[:80]}")

        if not texto:
            print("[GEMINI] texto vazio — Gemini não retornou nada")
            return vazio, ""

        # Parse JSON — limpar markdown se presente
        clean = _re.sub(r"```json\s*|\s*```", "", texto).strip()
        parsed = json.loads(clean)

        dados = {
            "estabelecimento": parsed.get("estabelecimento") or None,
            "valor_total":     _norm_valor(parsed.get("valor_total")),
            "data":            _norm_data(str(parsed.get("data") or "")),
        }
        print(f"[GEMINI] OK: {dados}")
        return dados, texto

    except httpx.TimeoutException:
        print(f"[GEMINI] TIMEOUT após 30s | b64={b64_kb}KB")
        return vazio, texto
    except json.JSONDecodeError as je:
        print(f"[GEMINI] JSON inválido: {je} | texto: {texto[:100]}")
        return vazio, texto
    except Exception as e:
        print(f"[GEMINI] ERRO inesperado: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return vazio, texto

# ── Fonte 3: Regex ────────────────────────────────────────────────────────────

def _regex_extrair(texto: str) -> dict:
    """
    Sempre executa se algum campo estiver faltando.
    Funciona mesmo sem nenhuma API disponível.
    """
    r = {"estabelecimento": None, "valor_total": None, "data": None}
    if not texto:
        return r

    # Valor — padrões em ordem de confiança decrescente
    for p in [
        r"(?:VALOR\s+TOTAL|TOTAL\s+A\s+PAGAR|VL\.?\s*TOTAL|TOTAL\s+GERAL)"
        r"\s*[:\-]?\s*R?\$?\s*([\d]{1,3}(?:\.[\d]{3})*[,\.][\d]{2})",
        r"(?<!\d)([\d]{1,3}(?:\.[\d]{3})*,[\d]{2})(?!\d)",
        r"R\$\s*([\d]+[,\.][\d]{2})",
    ]:
        ms = _re.findall(p, texto, _re.IGNORECASE | _re.MULTILINE)
        vs = [_norm_valor(m) for m in ms]
        vs = [v for v in vs if v]
        if vs:
            r["valor_total"] = max(vs)
            break

    # Data
    m = _re.search(r"(\d{2})[/\-](\d{2})[/\-](\d{4})", texto)
    if m:
        r["data"] = f"{m.group(3)}-{m.group(2)}-{m.group(1)}"

    # Estabelecimento — primeiras linhas não numéricas
    linhas = [l.strip() for l in texto.split("\n")
              if l.strip() and len(l.strip()) > 3
              and not _re.match(r"^[\d\.\-/:\s]+$", l.strip())]
    for linha in linhas[:6]:
        if len(linha) < 80 and not _re.match(r"^\d{2}[/\-]\d{2}", linha):
            r["estabelecimento"] = linha
            break

    print(f"[REGEX] {r}")
    return r

# ── Mesclagem ─────────────────────────────────────────────────────────────────

def _mesclar(fontes: list[tuple[str, dict]]) -> tuple[dict, list[str]]:
    """
    Mescla resultados campo a campo com prioridade da lista.
    Ex: Gemini trouxe valor, regex trouxe estabelecimento → ambos usados.
    """
    final = {"estabelecimento": None, "valor_total": None, "data": None}
    usadas: list[str] = []
    for nome, dados in fontes:
        contribuiu = False
        for campo in ["estabelecimento", "valor_total", "data"]:
            if final[campo] is None and dados.get(campo) is not None:
                final[campo] = dados[campo]
                contribuiu = True
        if contribuiu and nome not in usadas:
            usadas.append(nome)
        if all(final[c] is not None for c in final):
            break   # todos preenchidos — parar
    return final, usadas

# ── Endpoint /v2/ocr ──────────────────────────────────────────────────────────

@app.post("/v2/ocr")
async def ocr_cupom(imagem: UploadFile = File(...), qr_url: str = Form(default="")):
    """
    Pipeline OCR: QR params → Gemini 1.5-flash → Regex local.
    Sempre retorna status:success — campos null ficam editáveis no frontend.
    """
    # Ler imagem
    try:
        raw  = await imagem.read()
        mime = imagem.content_type or "image/jpeg"
        print(f"[OCR] imagem: {len(raw)} bytes | mime: {mime} | qr_url: {bool(qr_url)}")
        if not mime.startswith("image/"):
            return {"status": "error", "message": "Arquivo deve ser uma imagem"}
        if len(raw) > 10 * 1024 * 1024:
            return {"status": "error", "message": "Imagem muito grande (máx 10MB)"}
        if len(raw) < 100:
            print("[OCR] AVISO: imagem muito pequena — pode ser arquivo vazio")
        b64 = base64.b64encode(raw).decode()
    except Exception as e:
        return {"status": "error", "message": f"Erro ao ler imagem: {e}"}

    fontes_coletadas: list[tuple[str, dict]] = []
    texto_gemini = ""

    # 1. QR params (instantâneo)
    if qr_url:
        dados_qr = _qr_extrair(qr_url)
        if any(v is not None for v in dados_qr.values()):
            fontes_coletadas.append(("qr", dados_qr))

    # 2. Gemini — sempre tenta se tiver chave (não depende de faltam)
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    print(f"[OCR] gemini_key presente: {bool(gemini_key)}")

    dados_gem, texto_gemini = await _gemini_ocr(b64, mime, gemini_key)
    print(f"[OCR] gemini retornou: {dados_gem} | texto_len: {len(texto_gemini)}")

    # Adicionar gemini se retornou qualquer campo
    if any(v is not None for v in dados_gem.values()):
        fontes_coletadas.append(("gemini", dados_gem))

    # 3. Regex — sempre roda usando o texto do Gemini (mesmo se todos null)
    #    Isso garante que mesmo sem Gemini útil, o regex tenta extrair do texto
    dados_rx = _regex_extrair(texto_gemini)
    print(f"[OCR] regex retornou: {dados_rx}")
    if any(v is not None for v in dados_rx.values()):
        fontes_coletadas.append(("regex", dados_rx))

    # Mesclar tudo
    final, fontes_usadas = _mesclar(fontes_coletadas)
    categoria = _sugerir_cat(final.get("estabelecimento") or "")

    confs = {"qr": 0.8, "gemini": 1.0, "regex": 0.4}
    conf  = max((confs.get(f, 0) for f in fontes_usadas), default=0.0)
    fonte_principal = fontes_usadas[0] if fontes_usadas else "manual"

    print(f"[OCR] FINAL: fontes={fontes_usadas} | {final}")

    return {
        "status": "success",
        "data": {
            "estabelecimento": final["estabelecimento"],
            "valor_total":     final["valor_total"],
            "data":            final["data"],
            "categoria":       categoria,
            "fonte":           fonte_principal,
            "fontes":          fontes_usadas,
            "confianca":       conf,
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# V2 — DIAGNÓSTICO DE EMAIL + ESQUECI A SENHA
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/v2/debug-ocr")
async def debug_ocr():
    """Verifica todas as variáveis necessárias para o OCR."""
    gemini = os.environ.get("GEMINI_API_KEY", "")
    return {
        "status": "ok",
        "gemini_configurado": bool(gemini),
        "gemini_preview":     (gemini[:8] + "..." + gemini[-4:]) if gemini else "NÃO CONFIGURADA",
        "solucao": None if gemini else (
            "Acesse dashboard.render.com → muty-api → Environment → "
            "Add Variable: GEMINI_API_KEY = sua-chave"
        )
    }


@app.get("/v2/debug-email")
async def debug_email():
    """
    Diagnóstico: verifica se RESEND_API_KEY está configurada.
    Não envia email — apenas verifica a configuração.
    """
    chave = RESEND_API_KEY
    if not chave:
        return {
            "status": "error",
            "message": "RESEND_API_KEY não configurada no Render",
            "solucao": "Acesse dashboard.render.com > muty-api > Environment > Add Variable: RESEND_API_KEY = re_XXXXXXXX"
        }
    return {
        "status": "ok",
        "resend_configurado": True,
        "chave_preview": chave[:8] + "..." + chave[-4:],  # mostra só parte da chave
        "frontend_url": FRONTEND_URL,
    }


@app.post("/v2/forgot-password")
async def forgot_password(request: Request):
    """
    Esqueci a senha — envia email com link para redefinir.
    Por segurança, sempre retorna a mesma mensagem (não revela se email existe).
    """
    try:
        body  = await request.json()
        email = str(body.get("email", "")).strip().lower()

        ok_email, resultado = validar_email(email)
        if not ok_email:
            return {"status": "error", "message": "Email inválido"}

        db   = get_db()
        user = db.users.find_one({"email": resultado})

        MSG_PADRAO = "Se este email estiver cadastrado, você receberá um link para redefinir sua senha."

        if not user:
            # Segurança: não revelar que o email não existe
            return {"status": "success", "message": MSG_PADRAO}

        # Gerar token de reset
        reset_token  = secrets.token_urlsafe(32)
        reset_expira = datetime.utcnow() + timedelta(hours=1)  # expira em 1 hora

        db.users.update_one(
            {"email": resultado},
            {"$set": {"reset_token": reset_token, "reset_expira": reset_expira}}
        )

        enviado = enviar_email_reset_senha(resultado, user.get("nome", ""), reset_token)
        print(f"[AUTH] Reset senha solicitado: {resultado} | email_enviado={enviado}")

        return {"status": "success", "message": MSG_PADRAO}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


@app.post("/v2/reset-password")
async def reset_password(request: Request):
    """
    Redefinir senha com o token recebido por email.
    """
    try:
        body      = await request.json()
        token     = str(body.get("token", "")).strip()
        nova_senha = str(body.get("nova_senha", ""))

        if not token:
            return {"status": "error", "message": "Token obrigatório"}

        # Validar nova senha
        ok_senha, msg_senha = validar_senha(nova_senha)
        if not ok_senha:
            return {"status": "error", "message": msg_senha}

        db   = get_db()
        user = db.users.find_one({"reset_token": token})

        if not user:
            return {"status": "error", "message": "Link inválido ou já utilizado"}

        if datetime.utcnow() > user.get("reset_expira", datetime.utcnow()):
            db.users.update_one(
                {"reset_token": token},
                {"$unset": {"reset_token": "", "reset_expira": ""}}
            )
            return {"status": "error", "message": "Link expirado. Solicite um novo em /v2/forgot-password"}

        # Atualizar senha e remover token
        db.users.update_one(
            {"reset_token": token},
            {
                "$set":   {"senha_hash": hash_senha(nova_senha), "updated_at": datetime.utcnow()},
                "$unset": {"reset_token": "", "reset_expira": ""}
            }
        )

        print(f"[AUTH] Senha redefinida: {user['email']}")
        return {"status": "success", "message": "Senha redefinida com sucesso! Faça login com sua nova senha."}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Erro: {str(e)}"}


# ══════════════════════════════════════════════════════════════════════════════
# V2 — NOTA FISCAL QR CODE
# ══════════════════════════════════════════════════════════════════════════════

_HEADERS_NF = {
    "User-Agent":      "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":   "max-age=0",
    "Sec-Fetch-Dest":  "document",
    "Sec-Fetch-Mode":  "navigate",
    "Sec-Fetch-Site":  "none",
    "Sec-Fetch-User":  "?1",
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

def _limpar_html(texto: str) -> str:
    """Remove tags HTML e espaços extras."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", texto)).strip()

def _extrair_valor(html: str) -> float:
    """
    Extrai valor total da NFC-e.
    Tenta múltiplos padrões em ordem de prioridade.
    """
    # Padrão 1: atributos data-* usados por portais modernos
    # ex: data-valor="125.90" ou data-total="125.90"
    m = re.search(r'data-(?:valor|total|preco)[^\s=]*\s*[=:]\s*[\"\']?([\d]+[.,][\d]{2})', html, re.IGNORECASE)
    if m:
        try:
            v = float(m.group(1).replace(",", "."))
            if 0.01 < v < 100000: return v
        except: pass

    # Padrão 2: campos específicos de NFC-e (estrutura comum das SEFAZs)
    padroes_nfce = [
        r'(?:Valor\s+Total|Total\s+da\s+Nota|Total\s+NF-e|Vl\.?\s*Total)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
        r'(?:TOTAL|Total\s+a\s+Pagar|Total\s+Pagar)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
        r'(?:Valor\s+a\s+Pagar|Pagar)\s*[:\-]?\s*R?\$?\s*([\d]{1,6}[.,][\d]{2})',
    ]
    for p in padroes_nfce:
        matches = re.findall(p, html, re.IGNORECASE)
        if matches:
            valores = []
            for m in matches:
                try:
                    v = float(m.replace(".", "").replace(",", "."))
                    if 0.01 < v < 100000: valores.append(v)
                except: pass
            if valores: return max(valores)

    # Padrão 3: qualquer R$ seguido de valor (fallback)
    todos = []
    for m in re.findall(r'R\$\s*([\d]{1,6}[.,][\d]{2})', html, re.IGNORECASE):
        try:
            v = float(m.replace(".", "").replace(",", "."))
            if 0.01 < v < 100000: todos.append(v)
        except: pass
    if todos: return max(todos)

    return 0.0

def _extrair_estabelecimento(html: str) -> str:
    """
    Extrai nome do estabelecimento da NFC-e.
    Tenta múltiplos padrões compatíveis com diferentes SEFAZs.
    """
    # Padrão 1: classes CSS específicas de portais NFC-e
    padroes_classe = [
        r'<[^>]*class="[^"]*(?:NomeEmit|nome-emit|razaoSocial|nomeEmpresa|nome_emit)[^"]*"[^>]*>(.*?)</',
        r'<[^>]*id="[^"]*(?:NomeEmit|nomeEmit|razaoSocial)[^"]*"[^>]*>(.*?)</',
    ]
    for p in padroes_classe:
        m = re.search(p, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = _limpar_html(m.group(1))
            if 3 < len(texto) < 120: return texto

    # Padrão 2: estrutura textual comum
    padroes_texto = [
        r'(?:Razão\s+Social|Emitente|Empresa)[:\s]+([A-Z][^<\n]{3,80})',
        r'<title[^>]*>([^<]{5,80})</title>',
    ]
    for p in padroes_texto:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            texto = _limpar_html(m.group(1)).strip()
            if 3 < len(texto) < 120: return texto

    # Padrão 3: primeiro <strong> ou <h1> da página
    for tag in [r'<h1[^>]*>(.*?)</h1>', r'<strong[^>]*>(.*?)</strong>']:
        m = re.search(tag, html, re.IGNORECASE | re.DOTALL)
        if m:
            texto = _limpar_html(m.group(1))
            if 3 < len(texto) < 120: return texto

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

        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            html = None
            ultimo_erro = ""

            # Tentar com 2 User-Agents diferentes (alguns portais bloqueiam mobile)
            user_agents = [
                _HEADERS_NF["User-Agent"],
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ]

            for ua in user_agents:
                try:
                    headers = {**_HEADERS_NF, "User-Agent": ua}
                    resp = await client.get(url, headers=headers)

                    # Verificar se foi bloqueado
                    if resp.status_code in [403, 429, 503]:
                        ultimo_erro = f"Bloqueado (HTTP {resp.status_code})"
                        continue

                    resp.raise_for_status()
                    html = resp.text

                    # Verificar se o HTML tem conteúdo útil
                    if len(html) < 500:
                        ultimo_erro = "HTML muito curto — possível bloqueio"
                        html = None
                        continue

                    # Verificar se foi bloqueado via conteúdo
                    termos_bloqueio = ["acesso bloqueado", "acesso negado", "access denied",
                                       "403 forbidden", "blocked", "captcha", "bot detection"]
                    if any(t in html.lower() for t in termos_bloqueio):
                        ultimo_erro = "Portal retornou página de bloqueio"
                        html = None
                        continue

                    break  # HTML válido encontrado

                except httpx.TimeoutException:
                    ultimo_erro = "Timeout"
                    continue
                except httpx.HTTPStatusError as e:
                    ultimo_erro = f"HTTP {e.response.status_code}"
                    continue
                except Exception as e:
                    ultimo_erro = str(e)
                    continue

            if html is None:
                return {
                    "status": "error",
                    "message": f"Portal da SEFAZ bloqueou o acesso automático ({ultimo_erro}). "
                               f"Use o modo manual ou tire foto do cupom.",
                    "code": "sefaz_blocked"
                }

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
