import pytest
from auth_server import app, db
from contextlib import contextmanager


JWT_SECRET = "your_jwt_secret"
JWT_ALGORITHM = "HS256"


@contextmanager
def client_session(client, data):
    with client.session_transaction() as sess:
        sess.update(data)
    yield


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client
    with app.app_context():
        db.drop_all()


def test_register_client(client):
    response = client.post(
        "/register_client",
        json={"name": "Test App", "redirect_uris": ["http://localhost:5000/callback"]},
    )
    assert response.status_code == 201
    data = response.get_json()
    assert "client_id" in data
    assert "client_secret" in data
    assert data["redirect_uris"] == ["http://localhost:5000/callback"]


def test_register_user(client):
    response = client.post(
        "/register_user", data={"username": "test_user", "password": "password123"}
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data["message"] == "User test_user registered successfully!"


def test_authorize(client):
    # Register client
    response = client.post(
        "/register_client",
        json={"name": "Test App", "redirect_uris": ["http://localhost:5000/callback"]},
    )
    client_data = response.get_json()

    # Register user
    client.post(
        "/register_user", json={"username": "test_user", "password": "password123"}
    )

    # Log in user and set session
    with client_session(client, {"user": "test_user"}):
        # Authorize client
        response = client.get(
            "/authorize",
            query_string={
                "client_id": client_data["client_id"],
                "redirect_uri": "http://localhost:5000/callback",
                "scope": "read",
                "state": "xyz",
            },
        )
        assert response.status_code == 200

        # Approve authorization
        response = client.post(
            "/authorize",
            data={"approve": "yes"},
            query_string={
                "client_id": client_data["client_id"],
                "redirect_uri": "http://localhost:5000/callback",
                "scope": "read",
                "state": "xyz",
            },
        )
        assert response.status_code == 302
        assert "code=" in response.location
        assert "state=xyz" in response.location

        # Extract authorization code from redirect URI
        code = response.location.split("code=")[1].split("&")[0]
        assert len(code) > 0


def test_token(client):
    # Register client
    response = client.post(
        "/register_client",
        json={"name": "Test App", "redirect_uris": ["http://localhost:5000/callback"]},
    )
    client_data = response.get_json()

    # Register user
    client.post(
        "/register_user", json={"username": "test_user", "password": "password123"}
    )

    # # Log in user
    # client.post("/login", data={"username": "test_user", "password": "password123"})

    # Log in user and set session
    with client_session(client, {"user": "test_user"}):
        # Authorize client and get authorization code
        client.get(
            "/authorize",
            query_string={
                "client_id": client_data["client_id"],
                "redirect_uri": "http://localhost:5000/callback",
                "scope": "read",
                "state": "xyz",
            },
        )
        response = client.post(
            "/authorize",
            data={"approve": "yes"},
            query_string={
                "client_id": client_data["client_id"],
                "redirect_uri": "http://localhost:5000/callback",
                "scope": "read",
                "state": "xyz",
            },
        )
        code = response.location.split("code=")[1].split("&")[0]

        # Exchange authorization code for access and refresh tokens
        response = client.post(
            "/token",
            json={
                "grant_type": "authorization_code",
                "client_id": client_data["client_id"],
                "client_secret": client_data["client_secret"],
                "code": code,
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 900

        # Use refresh token to get a new access token
        refresh_token = data["refresh_token"]
        response = client.post(
            "/token",
            json={
                "grant_type": "refresh_token",
                "client_id": client_data["client_id"],
                "client_secret": client_data["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 900
