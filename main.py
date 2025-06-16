from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = "supersecreto"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Administrador",
        "hashed_password": "$2b$12$QKfwnmiYI2F/dw3I2J1U.eFXNwI42u6Uy6yMKtA4Xud1KQob6ZyPS", # contraseña: admin123
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autorizado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return fake_users_db[username]

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/pedidos")
async def get_pedidos(current_user: dict = Depends(get_current_user)):
    # Solo usuarios autenticados pueden acceder aquí
    return [
        {"id": 1, "cliente": "Abel", "total": 50},
        {"id": 2, "cliente": "JVT", "total": 100},
    ]

@app.get("/")
def root():
    return {"msg": "Backend Conexiones Chulas en marcha 🚀"}

