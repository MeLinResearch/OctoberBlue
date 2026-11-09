# syntax=docker/dockerfile:1
# Fixed trusted verifier/replay code, separate from target and host state.
FROM python:3.11-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
COPY docker/trusted-requirements.txt /tmp/trusted-requirements.txt
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    python -m pip install --no-cache-dir --require-hashes -r /tmp/trusted-requirements.txt \
    && rm /tmp/trusted-requirements.txt
COPY src/octoberblue /usr/local/lib/python3.11/site-packages/octoberblue
COPY LICENSE /usr/share/licenses/octoberblue/LICENSE
RUN chmod -R a+rX /usr/local/lib/python3.11/site-packages/octoberblue
WORKDIR /tmp
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
CMD ["python", "-I", "-B", "-m", "octoberblue.ticket_verifier_worker"]
