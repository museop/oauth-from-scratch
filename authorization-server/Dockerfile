# Use the official Python image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the application code to the working directory
COPY . /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Expose the port Flask will run on
EXPOSE 5000

# Command to run Gunicorn with Flask app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app", "--log-level", "debug"]