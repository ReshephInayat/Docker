from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Annotated

ALGORITHM: str = "HS256"
SECRET_KEY: str = "A Secure Secret Key"


fake_users_db: dict[str, dict[str, str]] = {
    "ameenalam": {
        "username": "ameenalam",
        "full_name": "Ameen Alam",
        "email": "ameenalam@example.com",
        "password": "ameenalamsecret",
    },
    "mjunaid": {
        "username": "mjunaid",
        "full_name": "Muhammad Junaid",
        "email": "mjunaid@example.com",
        "password": "mjunaidsecret",
    },
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(subject: str, expires_delta: timedelta):
    expire = datetime.utcnow() + expires_delta
    to_encode = {"exp": expire, "sub": subject}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        return decoded_token
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]
):

    user_in_db = fake_users_db.get(form_data.username)
    if not user_in_db:
        raise HTTPException(status_code=400, detail="Incorrect username")

    if user_in_db["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token = create_access_token(
        subject=form_data.username, expires_delta=timedelta(minutes=30)
    )

    return {"username": form_data.username, "access_token": access_token}


@app.get("/all-users")
def get_all_users(token:Annotated[str, Depends(oauth2_scheme)]):
    return fake_users_db


@app.get("/get_token")
async def get_token(name: str):
    access_token = create_access_token(subject=name, expires_delta=timedelta(minutes=2))
    return {"access_token": access_token}


@app.get("/decode_token")
def decoded_token(token: str):
    try:
        decoded_data = decode_token(token)
        return decoded_token
    except JWTError as e:
        return {"error": str(e)}
