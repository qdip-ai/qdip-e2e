# One-shot non-cron Railway job, isolated SDK-383 sealed delivery E2E.
# Runtime credentials come only from Railway service references; never at build.
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/scripts
WORKDIR /app
COPY scripts/sdk383_sealed_railway_e2e.py scripts/sdk383_sealed_worker_lifecycle_e2e.py ./scripts/
COPY tests/test_sdk383_railway_guardrails.py ./tests/
RUN python -m compileall -q scripts && python -m unittest discover -s tests -p test_sdk383_railway_guardrails.py -v && useradd -r -u 10001 qa
USER qa
CMD ["python", "-u", "scripts/sdk383_sealed_railway_e2e.py"]
