FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p data backups logs

ENV NOVADNS_DB=/app/data/novadns.sqlite \
    NOVADNS_BIND=0.0.0.0 \
    NOVADNS_DNS_PORT=53 \
    NOVADNS_WEB_PORT=8080

EXPOSE 53/udp 53/tcp 8080/tcp
VOLUME ["/app/data", "/app/backups", "/app/logs"]

CMD ["python3", "run.py"]
