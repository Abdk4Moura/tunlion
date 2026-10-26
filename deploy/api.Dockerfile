# Tunlion signaling API — production image.
# Build context is the REPO ROOT (see docker-compose.yml), so paths are backend/*.
FROM python:3.12-slim

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Native WebSockets via eventlet; single worker because the room registry is
# in-memory (see deploy/README.md → "Scaling").
# --worker-connections: every connected device holds one eventlet greenlet, and
# gunicorn's default of 1000 is a hard wall (the 1001st websocket hangs). The
# 2026-10-26 load test at 1 CPU / 512m held 4000 at about 430 MB, under the OOM cap.
ENV FIL_ASYNC_MODE=eventlet PORT=8000
EXPOSE 8000
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "--worker-connections", "4000", "-b", "0.0.0.0:8000", "app:app"]
