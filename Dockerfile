# Required: pass an immutable digest, e.g. python@sha256:<64 lowercase hex>.
# Docker fails before a build starts when release automation omits this argument.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG PYTHON_IMAGE
# Reject a tag or malformed digest before installing TraceGuard into the image.
RUN python -c 'import os, re; image = os.environ.get("PYTHON_IMAGE", ""); assert re.fullmatch(r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}", image), "PYTHON_IMAGE must be an immutable sha256 digest"'
WORKDIR /app
RUN useradd --system --uid 10001 traceguard
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
USER 10001
EXPOSE 8080
CMD ["traceguard-api"]
