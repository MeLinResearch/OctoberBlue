# Development-only data-only target image. No model SDK or credentials.
# Pin base image to an immutable digest before hosted or adversarial deployments.
FROM python:3.11-slim-bookworm
WORKDIR /app
COPY --chmod=0444 src/octoberblue/__init__.py /app/octoberblue/__init__.py
COPY --chmod=0444 src/octoberblue/target_worker.py /app/octoberblue/target_worker.py
COPY --chmod=0444 src/octoberblue/ticket_target_worker.py /app/octoberblue/ticket_target_worker.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
CMD ["python", "-m", "octoberblue.target_worker"]
