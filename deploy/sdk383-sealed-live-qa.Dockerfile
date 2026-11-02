# One-shot non-cron Railway job, isolated SDK-383 sealed delivery E2E.
# Runtime credentials come only from Railway service references; never at build.
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY scripts/sdk383_sealed_railway_e2e.py ./scripts/
RUN python -m compileall -q scripts && useradd -r -u 10001 qa
USER qa
CMD ["python", "-u", "scripts/sdk383_sealed_railway_e2e.py"]
