"""Small intentionally unsafe target for validating the Docker quick start."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.get("/run")
def run_command() -> str:
    """Run an untrusted command so scanners have a deterministic smoke finding."""
    command = request.args.get("command", "echo smoke")
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        shell=True,
        text=True,
    )
    return completed.stdout
