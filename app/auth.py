import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

# 🚨 In a production app, keep this secret safe in an environment variable!
SECRET_KEY = "SUPER_SECRET_FRAUD_DETECTION_KEY_CHANGE_ME"
ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = 2

def hash_password(password: str) -> str:
    # Generates a random salt and securely hashes the plain text password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Safely checks if the provided password matches the stored hash
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(username: str) -> str:
    # Creates a short-lived secure JWT session login token
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRATION_HOURS)
    payload = {
        "sub": username,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> str | None:
    # Decodes and verifies a JWT token to extract the username
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None
