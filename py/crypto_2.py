from flask import Flask, jsonify, request
import bitcoin, hashlib, binascii, base58
import eth_keys, binascii
import json

app =Flask(__name__)
@app.route('/crypto2/eth_sign', methods=["POST"])
def eth_sign():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["skey", "msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    # TODO: Not Implemented Yet
	
    response = {"signature": "TODO",
                "msg": "TODO"}

    return json.dumps(response), 201

@app.route('/crypto2/eth_sign_to_addr', methods=["POST"])
def eth_sign_to_addr():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["signature", "msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    # TODO: Not Implemented Yet
	
    response = {"address": "TODO"}

    return json.dumps(response), 201

@app.route('/crypto2/eth_sign_verify', methods=["POST"])
def eth_sign_verify():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["address", "signature", "msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    # TODO: Not Implemented Yet
	
    response = {"valid": "TODO"}
	
    return json.dumps(response), 201

@app.route('/crypto2/btc_skey_to_addr', methods=["POST"])
def btc_skey_to_addr():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["skey"]
    if not all(k in values for k in required):
        return "Missing values", 400

    # TODO: Not Implemented Yet
	
    response = {"address": "TODO"}
	
    return json.dumps(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

