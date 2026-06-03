"""
app/auth.py
JWT verification — used by routes.py/dashboard.

V5 sink: check_token() accepts algorithm='none', meaning a token with
no signature is accepted as valid. Combined with the open redirect in
routes.py, an attacker can forge a token and be redirected anywhere.

Cross-file taint chain:
  routes.py  → request.args["token"]  (source)
  auth.py    → check_token()          (accepts alg=none — auth bypass)
  routes.py  → redirect(next_url)     (sink — arbitrary redirect)
"""
import jwt

SECRET = "dev-secret"

def check_token(token: str) -> bool:
    if not token:
        return False
    try:
        # algorithms list includes "none" — accepts unsigned tokens.
        jwt.decode(token, SECRET, algorithms=["HS256", "none"])
        return True
    except jwt.InvalidTokenError:
        return False

def make_token(user_id: int) -> str:
    return jwt.encode({"uid": user_id}, SECRET, algorithm="HS256")
