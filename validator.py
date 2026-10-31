#!/usr/bin/env python3
pass
import os, base64, subprocess, struct
from flask import Flask, request, jsonify, Response

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_BIN = os.environ.get(
    "HOST_BIN",
    os.path.join(HERE, "host") if os.path.exists(os.path.join(HERE, "host"))
    else os.path.join(os.path.dirname(HERE), "build", "host"))

MAX_MODULE = 64 * 1024

app = Flask("bhargava-challenge-seal")

LANDING = (
    "Bhargava's Challenge — the bow beyond the bow (Mithila, Chapter II).\n"
    "Parashurama hands you the old Pinaka bytecode (PNK1, gen1) and the new Sharnga bytecode\n"
    "(SRNG, gen2), and the native host that strings them together. String the bow.\n\n"
    "POST /bhargava/string-the-bow  with JSON:\n"
    "  { \"gen1_b64\": \"<base64 of your PNK1 module>\",\n"
    "    \"gen2_b64\": \"<base64 of your SRNG module>\" }\n\n"
    "The host links gen1's exports into gen2's imports over one shared arena and runs them.\n"
    "It returns whatever its ASTRA opcode releases — and ASTRA releases the flag only when the\n"
    "bow is truly strung.\n"
)


@app.get("/")
def index():
    return Response(LANDING, mimetype="text/plain")


@app.post("/bhargava/string-the-bow")
def string_the_bow():
    d = request.get_json(force=True, silent=True) or {}
    try:
        g1 = base64.b64decode(d.get("gen1_b64", ""), validate=True)
        g2 = base64.b64decode(d.get("gen2_b64", ""), validate=True)
    except Exception:
        return jsonify(status="rejected", message="gen1_b64 / gen2_b64 must be valid base64"), 400
    if not g1 or not g2:
        return jsonify(status="rejected", message="both gen1_b64 and gen2_b64 are required"), 400
    if len(g1) > MAX_MODULE or len(g2) > MAX_MODULE:
        return jsonify(status="rejected", message="module too large"), 400

    blob = struct.pack("<I", len(g1)) + g1 + struct.pack("<I", len(g2)) + g2
    try:
        p = subprocess.run([HOST_BIN], input=blob, capture_output=True, timeout=10,
                           env=dict(os.environ))
    except FileNotFoundError:
        return jsonify(status="error", message="host binary unavailable"), 500
    except subprocess.TimeoutExpired:
        return jsonify(status="rejected", message="host timed out"), 408

    out = p.stdout.decode(errors="replace").strip()
    if p.returncode == 0 and out.startswith("PINAKA-ASTRA-RELEASED "):
        flag = out[len("PINAKA-ASTRA-RELEASED "):]
        return jsonify(status="astra-released",
                       proclamation="Parashurama lowers the Sharnga: the bow is strung",
                       host_output=out, flag=flag)
    return jsonify(status="sealed-or-rejected",
                   message="the bow is not strung; the astra stays sealed",
                   host_output=out, host_exit=p.returncode), 409


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8060)), threaded=True)
