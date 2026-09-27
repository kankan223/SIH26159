# SecureMailScope — production image (SIH26159)
# Passive-analysis engine: no active probing, no outbound connections, no inbound mail.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# gunicorn wheels are prebuilt — no compiler toolchain needed in the image
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY app.py analyzer.py rules.py risk_engine.py ai_assist.py anomaly.py \
     ml_anomaly.py pcap_reader.py tls_parser.py cert_analysis.py \
     upload_pipeline.py audit.py report.py wsgi.py ./
COPY templates/ templates/
COPY static/ static/
COPY data/ data/

# non-root runtime user; reports/ and config/ are the only writable paths
RUN useradd -r -u 900 sms && mkdir -p reports config \
 && chown -R sms:sms reports config
USER sms

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2)" || exit 1

CMD ["gunicorn", "--workers", "2", "--threads", "4", "--timeout", "120", \
     "--bind", "0.0.0.0:8000", "wsgi:app"]
