from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

import requests
from requests import request
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import base64
import json
import os

class User(BaseModel):
    email: EmailStr
    password: str
    username: str

load_dotenv()

client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
redirect_uri = os.getenv('REDIRECT_URI')
API_URL = os.getenv('API_URL')
auth_url = os.getenv('AUTH_URL')
token_url = os.getenv('TOKEN_URL')
scope = 'user-library-read user-top-read playlist-read-private'
sp_access_token = None
sp_refresh_token = None


app = FastAPI()

db: list[User] = []

def get_token(code):
    url = token_url
    headers = {
        'content-type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'authorization_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'code': code,
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid code")
    return response.json()


token = get_token()

def refresh_token(refreshed_token):
    url = token_url
    headers = {
        'content-type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refreshed_token,
        'client_id': client_id,
        'client_secret': client_secret,
    }
    result = requests.post(url, headers=headers, data=data)
    json_result = json.loads(result.text)
    refreshed_token = json_result['refresh_token']
    if result.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    return refreshed_token

def get_auth_header(token):
    return {'Authorization': f'Bearer {token}'}

@app.get('/login')

def login():
    authentification_url =  (f'{auth_url}?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}')
    return RedirectResponse(authentification_url)

@app.get('/callback')

def callback(code):
    global sp_access_token, sp_refresh_token
    try:
        sp_token = get_token()
        sp_access_token = sp_token.get('access_token')
        sp_refresh_token = sp_token.get('refresh_token')
        return {'message': 'Token received', 'token_data': sp_token}
    
    except Exception as e:
        return Response({'message': 'Error', 'error': str(e)}, status=400)

@app.post("/api/users")

def create_users(user: User):
    new_user = User(
        email=user.email,
        password=user.password,
        username=user.username,
        user_id = len(db) + 1,
        )
    db.append(new_user)
    return {"message": "Signup successful"}

@app.get("/api/all_users")

def get_users():
    return db

@app.get("/api/users/{user_id}")

def get_user(user_id: int):
    for user in db:
        if user.id == user_id:
            return user
        if not user.id == user_id:
            raise HTTPException(status_code=404, detail="User not found")
    return db

@app.put("/api/users/{user_id}")

def update_user(user: User, user_id: int):
    for i, user in enumerate(db):
        if user.id == user_id:
            db[i] = user
        if not user == user_id:
            raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User updated"}

@app.delete("/api/users/{user_id}")

def delete_user(user_id: int):
    for user in db:
        if user.id == user_id:
            db.remove(user)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted"}

@app.get("/api/me/top-tracks")

def get_top_tracks():
    headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    response = requests.get(f"{API_URL}/me/top/tracks", headers=headers)
    top_tracks_data = response.json()
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Error")
    return Response(top_tracks_data)

@app.get("/api/me/top-artists")

def get_top_artists():
    headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    response = requests.get(f"{API_URL}/me/top/artists", headers=headers)
    top_artists_data = response.json()
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Error")
    return Response(top_artists_data)