from flask import Flask, request, jsonify, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import bcrypt
import uuid
import jwt
import hashlib
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
    f"@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '5432')}"
    f"/{os.getenv('DB_NAME', 'oauth_db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Secret key for JWT
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"


# Database models
class User(db.Model):
    username = db.Column(db.String(255), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Client(db.Model):
    client_id = db.Column(db.String(255), primary_key=True)
    client_secret = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    redirect_uris = db.Column(db.Text, nullable=False)  # JSON encoded
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuthorizationCode(db.Model):
    code = db.Column(db.String(255), primary_key=True)
    client_id = db.Column(
        db.String(255), db.ForeignKey("client.client_id"), nullable=False
    )
    username = db.Column(db.String(255), db.ForeignKey("user.username"), nullable=False)
    scope = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class RefreshToken(db.Model):
    token = db.Column(db.String(255), primary_key=True)
    client_id = db.Column(
        db.String(255), db.ForeignKey("client.client_id"), nullable=False
    )
    username = db.Column(db.String(255), db.ForeignKey("user.username"), nullable=False)
    scope = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# Initialize the database
with app.app_context():
    db.create_all()


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
    new_client = Client(
        client_id=client_id,
        client_secret=client_secret,
        name=data["name"],
        redirect_uris=",".join(
            data["redirect_uris"]
        ),  # Store as a comma-separated string
    )
    db.session.add(new_client)
    db.session.commit()

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
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Both username and password are required."}), 400

        if db.session.get(User, username):
            return jsonify({"error": "Username already exists."}), 400

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        new_user = User(
            username=username, password_hash=hashed_password.decode("utf-8")
        )
        db.session.add(new_user)
        db.session.commit()

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

        user = db.session.get(User, username)
        if not user or not bcrypt.checkpw(
            password.encode("utf-8"), user.password_hash.encode("utf-8")
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

    # Ensure user is logged in
    if "user" not in session:
        return redirect(url_for("login", next=request.url))

    client = db.session.get(Client, client_id)
    if not client or redirect_uri not in client.redirect_uris.split(","):
        return jsonify({"error": "Invalid client or redirect URI"}), 400

    if request.method == "POST":
        if "approve" in request.form:
            code = str(uuid.uuid4())
            new_code = AuthorizationCode(
                code=code,
                client_id=client_id,
                username=session["user"],
                scope=scope,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            db.session.add(new_code)
            db.session.commit()
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


def generate_access_token(username: str, client_id: str, scope: str) -> str:
    payload = {
        "user": username,
        "client_id": client_id,
        "scope": scope,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def process_authorization_code_grant(data: dict):
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")
    code = data.get("code", "")

    client = db.session.get(Client, client_id)
    if not client or client.client_secret != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    auth_code = db.session.get(AuthorizationCode, code)
    if not auth_code or auth_code.client_id != client_id:
        return jsonify({"error": "invalid_grant"}), 400

    expires_at = auth_code.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.session.delete(auth_code)
        db.session.commit()
        return jsonify({"error": "invalid_grant"}), 400

    # Generate Access Token
    access_token = generate_access_token(auth_code.username, client_id, auth_code.scope)

    # Generate Refresh Token
    refresh_token = str(uuid.uuid4())

    # Store hashed refresh token
    new_refresh_token = RefreshToken(
        token=refresh_token,
        client_id=client_id,
        username=auth_code.username,
        scope=auth_code.scope,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.session.add(new_refresh_token)
    db.session.delete(auth_code)
    db.session.commit()

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

    client = db.session.get(Client, client_id)
    if not client or client.client_secret != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    # Validate refresh token
    stored_token = db.session.get(RefreshToken, refresh_token)

    if not stored_token:
        return jsonify({"error": "invalid_grant"}), 400

    expires_at = stored_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.session.delete(stored_token)
        db.session.commit()
        return jsonify({"error": "invalid_grant"}), 400

    # Generate a new Access Token
    access_token = generate_access_token(
        stored_token.username, client_id, stored_token.scope
    )

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
