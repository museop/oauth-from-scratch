# AUTHORIZATION FLOW

## 0. Register & Login

Register client:
- http://127.0.0.1:5000/register_client

Register user:
- http://127.0.0.1:5000/register_user

Login:
- http://127.0.0.1:5000/login


## 1. Authorize

Approve or Decline authorization.

- http://127.0.0.1:5000/authorize?client_id=client_id_123&redirect_uri=http://127.0.0.1:5000/callback

Actually, The redirect URI is a client's callback URI, but this example used the fake callback for demo.


## 2. Redirect to client's callback

Client receive the code.
```json
{
  "code": "456aa0f6-c420-491d-9f53-5583939195b8",
  "state": ""
}
```

## 3. Get authorization token

```sh
curl -d '{"grant_type": "authorization_code", "client_id": "client_id_123", "client_secret": "client_secret_123", "code": "d68ef271-08f3-40e7-89c8-bda6290232b5"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:5000/token
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJjbGllbnRfaWRfMTIzIiwidXNlciI6Im11c2VvcCIsInNjb3BlIjoiIiwiZXhwIjoxNzMzMzI2NTk5fQ.i-PciTYpRPIpbKlJvTnYCqFy7T-JzUKw1fXJZ-ltnw4",
  "expires_in": 900,
  "refresh_token": "3b1be7b8-ebc1-4a63-bbd0-475689b41f68",
  "token_type": "Bearer"
}
```

## 4. Refresh token

```sh
❯ curl -d '{"client_id": "client_id_123", "client_secret": "client_secret_123", "refresh_token": "3b1be7b8-ebc1-4a63-bbd0-475689b41f68", "grant_type": "refresh_token"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:5000/token
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoibXVzZW9wIiwiY2xpZW50X2lkIjoiY2xpZW50X2lkXzEyMyIsInNjb3BlIjoiIiwiZXhwIjoxNzMzMzI0NDc0fQ.tQfMjSoxPpu52g-J_7Ci7XMQubUNlNGRJZM1WRT_qZs",
  "expires_in": 900,
  "token_type": "Bearer"
}
```