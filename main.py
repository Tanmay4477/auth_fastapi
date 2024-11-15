from fastapi import FastAPI, HTTPException, Depends
from auth import AuthHandler
from pydantic import BaseModel
app = FastAPI()

class AuthSchema(BaseModel):
    username: str
    password: str

auth_handler = AuthHandler()
users = []

@app.post("/register", status_code=201)
def register(auth_details: AuthSchema):
    if any(x['username'] == auth_details.username for x in users):
        raise HTTPException(status_code=401, details = "Http exception raise kia h")
    hashed_password = auth_handler.get_password_hash(auth_details.password)
    users.append({
        'username': auth_details.username,
        'password': hashed_password
    })
    return {}

@app.post("/login", status_code=201)
def login(user_detail: AuthSchema):
    user = None
    for x in users:
        if x['username'] == user_detail.username:
            user = x
            break
    if(user is None):
        raise HTTPException(status_code=401, detail='Invalid username or password')
    elif(not auth_handler.verify_password(user_detail.password, user['password'])):
        raise HTTPException(status_code=401, detail='Invalid username or password')

    token = auth_handler.encode_token(user['username'])
    return {'token': token}

@app.get("/unprotected")
def unprotected():
    return {'hello': 'world'}

@app.get("/protected")
def protected(username = Depends(auth_handler.auth_wrapper)):
    return {'username': username}

