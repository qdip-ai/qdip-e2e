# Scoped PR #144 regression runner; used only by the existing Railway CI sandbox.
# No credentials, network-bound tests, or new Railway services are required.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY scripts/provision_rr_railway_qa.py scripts/rr_qa_railway_private_readback.py ./scripts/
COPY tests/test_rr_qa_private_readback.py ./tests/
RUN python -m compileall -q scripts tests
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_rr_qa_private_readback.py", "-v"]
