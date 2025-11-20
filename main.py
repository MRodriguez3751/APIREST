from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta, date
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
# Modelo de usuario
# -----------------------------------------
class UsuarioBase(BaseModel):
    username: str
    nombre: str
    apellidos: str
    email: str
    contraseña: str
    activo: bool

class Usuario(UsuarioBase):
    id: int
    class Config:
        from_attributes = True

class UsuarioCreate(UsuarioBase):
    username: str
    nombre: str
    apellidos: str
    email: str
    contraseña: str

class UsuarioUpdate(BaseModel):
    username: Optional[str] = None
    nombre: Optional[str] = None
    apellidos: Optional[str] = None
    email: Optional[str] = None
    contraseña: Optional[str] = None
    activo: Optional[bool] = None
    

# -----------------------------------------
# Modelo de Tareas
# -----------------------------------------
class TareaBase(BaseModel):
    titulo: str
    descripcion: str
    fecha_limite: date
    completada: bool

class Tarea(TareaBase):
    id: int
    usuario_id: int
    class Config:
        from_attributes = True

class TareaCreate(TareaBase):
    titulo: str
    descripcion: str
    fecha_limite: date
    completada: bool

class TareaUpdate(BaseModel):
    titulo: Optional[str] = None
    descripcion: Optional[str] = None
    fecha_limite: Optional[date] = None
    completada: Optional[bool] = None

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
def obtener_usuario_por_username(username: str):
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

    usuario = obtener_usuario_por_username(username)
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
    
# -------------------------
# Rutas de usuarios
# -------------------------
@app.post("/auth")
async def autenticar_usuario(form_data: OAuth2PasswordRequestForm = Depends()):
    usuario_db = obtener_usuario_por_username(form_data.username)
    if not usuario_db or not verificar_password(form_data.password, usuario_db["contraseña"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token = crear_token_de_acceso(data={"sub": usuario_db["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/usuarios")
async def obtener_usuarios():
    try:
        usuarios = supabase.table("usuarios").select("*").execute()
        return usuarios.data
    except Exception as e:
        return { "error": str(e) }

@app.get("/usuarios/{usuario_id}")
async def obtener_usuario_por_id(usuario_id: int):
    try:
        usuario = supabase.table("usuarios").select("*").eq("id", usuario_id).execute()
        return usuario.data
    except Exception as e:
        return { "error": str(e) }

@app.post("/usuarios")
async def crear_usuarios(usuario_data: UsuarioCreate):
    try:
        hashed_password = hash_password(usuario_data.contraseña)
        usuario_dict = usuario_data.model_dump()
        usuario_dict["contraseña"] = hashed_password 

        response = supabase.table("usuarios").insert([usuario_dict]).execute()
        return response.data
    except Exception as e:
        return {"error": str(e)}
    
@app.put("/usuarios/{usuario_id}")
async def actualizar_usuario(contraseña_actual: str, usuario_id: int, usuario_data: UsuarioUpdate, usuario: Usuario = Depends(obtener_usuario_actual)):
    if usuario["id"] != usuario_id:
        raise HTTPException(status_code=403, detail="No autorizado para actualizar este usuario")
    
    try:
        exist = supabase.table("usuarios").select("*").eq("id", usuario_id).execute()
        if not exist.data:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")
        
        usuario_db = exist.data[0]
        password_match = verificar_password(contraseña_actual, usuario_db["contraseña"])
        if not password_match:
            raise HTTPException(status_code=401, detail="Contraseña actual incorrecta.")

        update_data = {}
        if usuario_data.username is not None:
            update_data["username"] = usuario_data.username
        if usuario_data.nombre is not None:
            update_data["nombre"] = usuario_data.nombre
        if usuario_data.apellidos is not None:
            update_data["apellidos"] = usuario_data.apellidos
        if usuario_data.email is not None:
            update_data["email"] = usuario_data.email
        if usuario_data.contraseña is not None:
            hashed_password = hash_password(usuario_data.contraseña)
            update_data["contraseña"] = hashed_password
        if usuario_data.activo is not None:
            update_data["activo"] = usuario_data.activo
        if not update_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron campos para actualizar")

        response = supabase.table("usuarios").update(update_data).eq("id", usuario_id).execute()
        return response.data
    except Exception as e:
        return {"error": str(e)}

@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int, usuario: Usuario = Depends(obtener_usuario_actual)):
    try:
        response = supabase.table("usuarios").delete().eq("id", usuario_id).execute()
        return {"mensaje": f"Usuario con ID {usuario_id} eliminado exitosamente", "data": response.data}
    except Exception as e:
        return {"error": str(e)}
    
# -------------------------
# Rutas de tareas
# -------------------------

@app.get("/tareas")
async def obtener_tareas(usuario: Usuario = Depends(obtener_usuario_actual)):
    try:
        tareas = supabase.table("tareas").select("*").eq("usuario_id", usuario["id"]).execute()
        return tareas.data
    except Exception as e:
        return {"error": str(e)}

@app.post("/tareas")
async def crear_tareas(tarea_data: TareaCreate, usuario: Usuario = Depends(obtener_usuario_actual)):
    try:
        tarea_dict = tarea_data.model_dump()
        tarea_dict["usuario_id"] = usuario["id"]

        if isinstance(tarea_dict["fecha_limite"], date):
            tarea_dict["fecha_limite"] = tarea_dict["fecha_limite"].isoformat()
        
        response = supabase.table("tareas").insert([tarea_dict]).execute()
        return response.data
    except Exception as e:
        return {"error": str(e)}

@app.put("/tareas/{tarea_id}")
async def actualizar_tareas(tarea_id: int, tarea_data: TareaUpdate, usuario: Usuario = Depends(obtener_usuario_actual)):
    try:
        exist = supabase.table("tareas").select("*").eq("id", tarea_id).execute()
        if not exist.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada.")
        
        update_data = tarea_data.model_dump(exclude_unset=True)
        response = supabase.table("tareas").update(update_data).eq("id", tarea_id).execute()
        return response.data
    except Exception as e:
        return {"error": str(e)}

@app.delete("/tareas/{tarea_id}")
async def eliminar_tareas(tarea_id: int, usuario: Usuario = Depends(obtener_usuario_actual)):
    try:
        tarea = supabase.table("tareas").select("*").eq("id", tarea_id).eq("usuario_id", usuario["id"]).execute()
        if not tarea.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada o no autorizada.")

        response = supabase.table("tareas").delete().eq("id", tarea_id).execute()
        return {"mensaje": f"Tarea con ID {tarea_id} eliminada exitosamente", "data": response.data}
    except Exception as e:
        return {"error": str(e)}