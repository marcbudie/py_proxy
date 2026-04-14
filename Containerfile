FROM python:3.12-slim

WORKDIR /app

COPY proxy.py .

CMD ["python3", "proxy.py", "/app/config.json"]
