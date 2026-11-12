FROM python:3.12-slim
WORKDIR /honeypot
RUN pip install --no-cache-dir httpx asyncssh fastapi "uvicorn[standard]" python-multipart
COPY . .
