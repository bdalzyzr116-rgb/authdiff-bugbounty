# AuthDiff container image.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY authdiff ./authdiff

# Install the package (add ",http3" to include the experimental QUIC transport).
RUN pip install --upgrade pip && pip install ".[fast]"

# Drop privileges: never run a network scanner as root.
RUN useradd --create-home --uid 10001 authdiff
USER authdiff

ENTRYPOINT ["authdiff"]
CMD ["--help"]
