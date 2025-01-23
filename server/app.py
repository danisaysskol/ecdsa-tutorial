from flask import Flask, request, jsonify, render_template
from verify import verify_signature

app = Flask(__name__)

# Data store for the last received message and signature
latest_data = {"message": None, "signature": None}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # When the verify button is clicked
        if latest_data["message"] and latest_data["signature"]:
            is_valid = verify_signature(
                latest_data["message"], latest_data["signature"]
            )
            if is_valid:
                return render_template(
                    "index.html", status="Signature is valid!", color="green"
                )
            else:
                return render_template(
                    "index.html", status="Invalid signature!", color="red"
                )
        else:
            return render_template(
                "index.html",
                status="No message or signature received yet!",
                color="orange",
            )
    # Initial GET request to load the interface
    return render_template("index.html", status=None, color=None)


@app.route("/receive", methods=["POST"])
def receive():
    # Receive message and signature from the client
    data = request.get_json()
    try:
        latest_data["message"] = bytes.fromhex(data["message"])
        latest_data["signature"] = bytes.fromhex(data["signature"])
        return jsonify({"status": "success", "message": "Data received"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


if __name__ == "__main__":
    app.run(port=5001, debug=True)
