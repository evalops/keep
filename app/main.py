from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def index():
    cert_subject = request.headers.get("X-Client-Subject", "unknown")
    if cert_subject.startswith("Subject="):
        cert_subject = cert_subject.replace("Subject=", "", 1)
    device_id = request.headers.get("X-Device-ID", "unknown")
    return (
        f"Hello from keep protected app!\n"
        f"Client cert subject: {cert_subject}\n"
        f"Device ID: {device_id}\n"
    )


@app.route("/step-up", methods=["POST"])
def step_up():
    return jsonify({"status": "step-up required"}), 202
