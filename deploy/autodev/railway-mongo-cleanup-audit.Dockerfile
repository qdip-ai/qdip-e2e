# One-shot read-only Mongo cleanup evidence in the AutoDev staging private network.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir pymongo==4.13.2
WORKDIR /app
COPY scripts/autodev_mongo_cleanup_audit.py /app/audit.py
USER 65534:65534
CMD ["python", "-B", "/app/audit.py"]
