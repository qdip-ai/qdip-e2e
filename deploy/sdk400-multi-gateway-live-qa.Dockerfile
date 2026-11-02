# Isolated Railway staging-only two-Gateway Security Gate E2E runner.
# Contains no production credentials and performs no secrets readback.
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /qa
COPY scripts/sdk383_sealed_railway_e2e.py scripts/sdk383_sealed_worker_lifecycle_e2e.py scripts/sdk400_two_gateway_security_e2e.py ./scripts/
RUN python -m compileall -q scripts
USER 65532:65532
CMD ["python", "-u", "scripts/sdk400_two_gateway_security_e2e.py"]
