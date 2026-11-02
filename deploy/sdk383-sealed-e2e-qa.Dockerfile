# Disposable Railway QA build: syntax and fail-closed contract checks only.
# No project tokens and no live sealed delivery in this image.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/scripts
WORKDIR /app
COPY scripts/sdk383_sealed_railway_e2e.py scripts/sdk383_sealed_worker_lifecycle_e2e.py ./scripts/
COPY tests/test_sdk383_railway_guardrails.py ./tests/
RUN python -m compileall -q scripts
RUN python -m unittest discover -s tests -p 'test_sdk383_railway_guardrails.py' -v
CMD ["python", "-c", "print('SDK383_E2E_STATIC_GUARDRAILS_PASS', flush=True)"]
