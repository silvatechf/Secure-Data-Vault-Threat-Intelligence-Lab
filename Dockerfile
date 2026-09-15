# Dockerfile
#
# Builds and runs the main FastAPI application. The honeypot
# (app/honeypot/server.py) is a deliberately separate process -- see
# docker-compose.yml, which runs it as its own service, matching the
# "separate port, separate process" design explained in
# docs/week-07-08-threat-intelligence.md.

FROM python:3.12-slim

# cryptography and bcrypt need a C compiler to build from source on some
# architectures if no prebuilt wheel matches this exact image -- installed
# here, in the same stage, for simplicity. A more storage-optimized setup
# would use a multi-stage build to drop these afterward; noted as a
# reasonable next step rather than done here, to keep this Dockerfile easy
# to read end to end.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Security checklist item: "Docker image runs as non-root user." A
# container running as root means a container-escape vulnerability hands
# an attacker root on the host, not just an unprivileged account.
RUN groupadd --system appuser && useradd --system --gid appuser --create-home appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# keys/, logs/, and encrypted_storage/ are created at runtime by the app
# itself -- owning the whole /app tree upfront means the app can create
# them (and set the 600 permissions the file_permissions.py scanner
# expects) without ever needing root.
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
