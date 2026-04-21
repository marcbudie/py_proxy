FROM python:3.11-slim

WORKDIR /opt/py_proxy

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py .

# config.json wordt als volume gemount; certs ook als dat nodig is
VOLUME ["/opt/py_proxy/config.json"]

# Geen EXPOSE — container draait op het host network (--network host)

CMD ["python3", "/opt/py_proxy/proxy.py", "/opt/py_proxy/config.json"]
