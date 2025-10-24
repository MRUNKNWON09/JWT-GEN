from fastapi import FastAPI, HTTPException, Request
import requests
import jwt
from datetime import datetime, timedelta, timezone
import os

app = FastAPI()

# Config
JWT_SECRET = os.environ.get("JWT_SECRET", "change_this_secret")
JWT_ALG = os.environ.get("JWT_ALG", "HS256")
JWT_EXP_MINUTES = int(os.environ.get("JWT_EXP_MINUTES", "60"))

GARENA_GUEST_TOKEN_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

def call_garena_guest_token(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }

    try:
        r = requests.post(GARENA_GUEST_TOKEN_URL, headers=headers, data=data, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        return {"error": str(e)}

    try:
        return r.json()
    except Exception as e:
        return {"error": f"Failed to parse JSON: {e}"}

def make_internal_jwt(uid, external_token, external_open_id, extra_claims=None):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uid),
        "external_token": external_token,
        "external_open_id": external_open_id,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXP_MINUTES),
    }
    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

@app.get("/")
async def generate_jwt(request: Request):
    uid = request.query_params.get("Id")
    password = request.query_params.get("pass")

    if not uid or not password:
        raise HTTPException(status_code=400, detail="Id and pass query parameters are required")

    result = call_garena_guest_token(uid, password)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    access_token = result.get("access_token") or result.get("accessToken")
    open_id = result.get("open_id") or result.get("openId")

    if not access_token or not open_id:
        raise HTTPException(status_code=400, detail="Failed to get access_token or open_id")

    internal_jwt = make_internal_jwt(uid, access_token, open_id, extra_claims={"garena_response": result})

    return {
        "internal_jwt": internal_jwt,
        "external_access_token": access_token,
        "external_open_id": open_id,
        "garena_response": result
}
