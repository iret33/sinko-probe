FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY configs/ ./configs/

RUN pip install . && useradd --create-home --uid 10001 probe

# Reports land in /reports: docker run -v "$PWD:/reports" ... --html /reports/audit.html
USER probe
WORKDIR /reports

ENTRYPOINT ["sinko-probe"]
CMD ["--help"]
