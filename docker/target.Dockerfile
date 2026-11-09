# Fixed JSON-only target. No gateway, verifier, model SDK or credentials.
FROM python:3.11-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
WORKDIR /app
COPY --chmod=0444 src/octoberblue/__init__.py /usr/local/lib/python3.11/site-packages/octoberblue/__init__.py
COPY --chmod=0444 src/octoberblue/target_worker.py /usr/local/lib/python3.11/site-packages/octoberblue/target_worker.py
COPY --chmod=0444 src/octoberblue/ticket_target_worker.py /usr/local/lib/python3.11/site-packages/octoberblue/ticket_target_worker.py
COPY --chmod=0444 src/octoberblue/containment_probe.py /usr/local/lib/python3.11/site-packages/octoberblue/containment_probe.py
RUN chmod 0555 /app /usr/local/lib/python3.11/site-packages/octoberblue
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
CMD ["python", "-m", "octoberblue.target_worker"]
