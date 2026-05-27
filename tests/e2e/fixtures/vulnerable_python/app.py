"""Minimal long-running Flask app — VulBox E2E fixture only.

Exists so the built image has a Python web stack to fingerprint and a process
that stays up for the ART phase. Not meant to be reachable or useful.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "vulnerable python target\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
