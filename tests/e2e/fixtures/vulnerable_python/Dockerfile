# INTENTIONALLY VULNERABLE — VulBox E2E fixture only. Do not deploy.
#
# python:3.6-slim is EOL and ships a known set of Debian base-image CVEs, and
# the pinned Flask/Werkzeug stack adds Python-package findings — so Trivy
# results and stack detection (python + flask) are deterministic across runs.
FROM python:3.6-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

EXPOSE 5000
# Long-running server so the sandbox stays up for the ART phase
# (DockerManager.assert_running fails fast on a container that exits).
CMD ["python", "app.py"]
