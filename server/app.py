from flask import Flask, request, jsonify, render_template
from verify import verify_signature

app = Flask(__name__)

# Data store for the last received message and signature
latest_data = {"message": None, "signature": None}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Retrieve edited data from the form
        edited_message = request.form.get("message", "")
        edited_signature = request.form.get("signature", "")

        try:
            # Convert hex strings back to bytes
            edited_message_bytes = bytes.fromhex(edited_message)
            edited_signature_bytes = bytes.fromhex(edited_signature)

            # Verify the signature with the edited data
            is_valid = verify_signature(edited_message_bytes, edited_signature_bytes)
            if is_valid:
                status = "Signature is valid!"
                color = "green"
            else:
                status = "Invalid signature!"
                color = "red"
        except Exception as e:
            status = f"Error: {str(e)}"
            color = "orange"

        return render_template(
            "index.html",
            message=edited_message,
            signature=edited_signature,
            status=status,
            color=color,
        )

    # Initial GET request to load the interface with the latest data
    message = latest_data["message"].hex() if latest_data["message"] else ""
    signature = latest_data["signature"].hex() if latest_data["signature"] else ""
    return render_template("index.html", message=message, signature=signature, status=None, color=None)


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
