FROM python:3.11-slim
WORKDIR /app

# Install runtime deps
COPY setup.py pyproject.toml /app/
RUN pip install --no-cache-dir .

COPY src/ /app/src/
COPY README.md /app/

ENV PYTHONPATH=/app/src

ENTRYPOINT ["mcp-scan"]
