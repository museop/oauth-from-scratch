from flask import Flask, request, jsonify, redirect, session, url_for
from datetime import datetime, timedelta, UTC
import bcrypt
import uuid
import jwt
import hashlib

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Secret key for JWT
JWT_SECRET = "your_jwt_secret"
JWT_ALGORITHM = "HS256"

# In-memory database (for demo purposes)
CLIENTS = {
    "client_id_123": {
        "name": "client_id_123_name",
        "client_secret": "client_secret_123",
        "redirect_uris": ["http://127.0.0.1:5000/callback"],
        "authorized_grants": ["authorization_code"],
    }
}
AUTHORICATION_CODES = {}
USERS = {"test_user": bcrypt.hashpw("password123".encode("utf-8"), bcrypt.gensalt())}
REFRESH_TOKENS = {}


# Client Registration Endpoint
@app.route("/register_client", methods=["POST"])
def register_client():
    """
    클라이언트 등록 엔드포인트
    요청 예제:
    {
        "name": "My App",
        "redirect_uris": ["http://localhost:5000/callback"]
    }
    """
    data = request.json
    if not data or "name" not in data or "redirect_uris" not in data:
        return (
            jsonify(
                {"error": 'Invalid input. "name" and "redirect_uris" are required.'}
            ),
            400,
        )

    client_id = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())

    CLIENTS[client_id] = {
        "name": data["name"],
        "redirect_uris": data["redirect_uris"],
        "client_secret": client_secret,
        "authorized_grants": ["authorization_code"],
    }

    return (
        jsonify(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": data["redirect_uris"],
            }
        ),
        201,
    )


# User Registration Endpoint
@app.route("/register_user", methods=["GET", "POST"])
def register_user():
    """
    사용자 등록 엔드포인트
    요청 예제:
    {
        "username": "new_user",
        "password": "secure_password"
    }
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Both username and password are required."}), 400

        if username in USERS:
            return jsonify({"error": "Username already exists."}), 400

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        USERS[username] = hashed_password

        return jsonify({"message": f"User {username} registered successfully!"}), 201

    return """
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>
    """


# User login simulation
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = USERS.get(username)
        if not hashed_password or not bcrypt.checkpw(
            password.encode("utf-8"), hashed_password
        ):
            return "Invalid credentials", 401

        session["user"] = username
        return redirect(request.args.get("next") or "/")
    return """
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    """


# Authorization endpoint
@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "")
    state = request.args.get("state", "")

    if "user" not in session:
        return redirect(url_for("login", next=request.url))

    if request.method == "POST":
        if "approve" in request.form:
            code = str(uuid.uuid4())
            AUTHORICATION_CODES[code] = {
                "client_id": client_id,
                "user": session["user"],
                "scope": scope,
                "expires": datetime.now(UTC) + timedelta(minutes=10),
            }
            return redirect(f"{redirect_uri}?code={code}&state={state}")
        return "Access Denied", 403

    return f"""
        <p>App {client_id} is requesting access to {scope}</p>
        <form method="post">
            <button name="approve" value="yes">Approve</button>
            <button name="deny" value="no">Deny</button>
        </form>
    """


# Token endpoint (JWT Token with Refresh Token)
@app.route("/token", methods=["POST"])
def token():
    data = request.get_json()
    grant_type = data.get("grant_type", "")

    if grant_type == "authorization_code":
        return process_authorization_code_grant(data)
    elif grant_type == "refresh_token":
        return process_refresh_token_grant(data)
    else:
        return jsonify({"error": "unsupported_grant_type"}), 400


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def process_authorization_code_grant(data: dict):
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")
    code = data.get("code", "")

    if client_id not in CLIENTS or CLIENTS[client_id]["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    auth_code = AUTHORICATION_CODES.get(code)
    if (
        not auth_code
        or auth_code["expires"] < datetime.now(UTC)
        or auth_code["client_id"] != client_id
    ):
        return jsonify({"error": "invalid_grant"}), 400

    # Generate Access Token
    payload = {
        "client_id": client_id,
        "user": auth_code["user"],
        "scope": auth_code["scope"],
        "exp": datetime.now(UTC) + timedelta(hours=1),  # Short-lived access token
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Generate Refresh Token
    refresh_token = str(uuid.uuid4())

    # Store hashed refresh token
    hashed_refresh_token = hash_token(refresh_token)
    REFRESH_TOKENS[hashed_refresh_token] = {
        "client_id": client_id,
        "user": auth_code["user"],
        "scope": auth_code["scope"],
        "expires": datetime.now(UTC) + timedelta(days=7),  # Longer-lived refresh token
    }

    # Clean up authorization code
    del AUTHORICATION_CODES[code]

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 900,  # 15 minutes
        }
    )


def process_refresh_token_grant(data: dict):
    refresh_token = data.get("refresh_token", "")
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")

    if client_id not in CLIENTS or CLIENTS[client_id]["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    # Validate refresh token
    hashed_refresh_token = hash_token(refresh_token)
    token_data = REFRESH_TOKENS.get(hashed_refresh_token)
    if not token_data or token_data["expires"] < datetime.now(UTC):
        return jsonify({"error": "invalid_grant"}), 400

    # Generate a new Access Token
    payload = {
        "user": token_data["user"],
        "client_id": client_id,
        "scope": token_data["scope"],
        "exp": datetime.now(UTC) + timedelta(minutes=15),  # Short-lived access token
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return jsonify(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,  # 15 minutes
        }
    )


# This callback must be in third-party app
@app.route("/callback", methods=["GET", "POST"])
def callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    return jsonify({"code": code, "state": state})


if __name__ == "__main__":
    app.run(debug=True)
