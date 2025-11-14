from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from supabase import create_client, Client
import os
from dotenv import load_dotenv

# -------------------------
# Inicializar FastAPI
# -------------------------
load_dotenv()
app = FastAPI(title="API de Alumnos", version="1.0.1")

# -------------------------
# Configuración de Supabase
# -------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------------
# Configuración de JWT
# -------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

# -----------------------------------------
# Funciones de utilidad para autenticación
# -----------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verificar_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def crear_token_de_acceso(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ---------------------------------------
# Funciones de autenticación de usuario
# ---------------------------------------
def obtener_usuario_por_nombre(username: str):
    try:
        response = supabase.table("usuarios").select("*").eq("username", username).execute()
        usuarios = response.data
        return usuarios[0] if usuarios else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al buscar usuario: {str(e)}")

def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido o expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

    usuario = obtener_usuario_por_nombre(username)
    if usuario is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")

    return usuario

# -------------------------
# Rutas de la API
# -------------------------
@app.get("/")
async def root():
    return {"message": "API de Alumnos con autenticación JWT."}

@app.get("/health")
async def health_check():
    try:
        supabase.table("usuarios").select("*").limit(1).execute()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}
