import json, time, base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_revocation_request(root_hash: str, reason: str, private_key: str, out_path: str = "revocation_request.json"):
    payload = {
        "action": "revoke_request",
        "root_hash": root_hash,
        "reason": reason,
        "timestamp": int(time.time())
    }
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    # Firma con la chiave privata di Salerno
    with open(private_key, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_package = {
        "payload": payload,
        "signature": base64.b64encode(signature).decode()
    }

    with open(out_path, "w") as f:
        json.dump(signed_package, f, indent=2)
    
    print(f"📦 Richiesta di revoca salvata in '{out_path}'")
    