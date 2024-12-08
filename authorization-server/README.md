# Authorization Server

## Requirements

- Python > 3.10
- PosgreSQL >= 15


Install python packages:
```sh
pip install -r requirements.txt
```

## Run

First, create `.env` file to set environment variables.

```
# Configure DB user (Required)
DB_USER=user

# Configure DB password (Required)
DB_PASSWORD=password

# Configure DB host (Required)
DB_HOST=localhost

# Configure DB port (Required)
DB_PORT=5432

# Configure DB name (Required)
DB_NAME=oauth_db

# Configure JWT Secret (Required)
JWT_SECRET="your_jwt_secret"
```

Then, run the server.

```sh
python app.py
```