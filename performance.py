import os, json, time
from salerno import (verify_signature_on_root, check_revocation, verify_signed_nonce)

def get_package_size(path="package_to_verify.json"):
    size_bytes = os.path.getsize(path)
    print(f"📦 Dimensione del pacchetto cifrato: {size_bytes / 1024:.2f} KB")
    return size_bytes

# Dimensione della credenziale selezionata per l'invio
def get_revealed_data_size(revealed_fields):
    total_size = 0
    for field in revealed_fields:
        field_json = json.dumps(field)
        total_size += len(field_json.encode('utf-8'))
    print(f"🔍 Dimensione totale dei campi rivelati + proof: {total_size / 1024:.2f} KB")
    return total_size

def analyze_merkle_proofs(revealed_fields):
    print("📊 Analisi delle Merkle Proofs...")
    total_nodes = 0
    for i, field in enumerate(revealed_fields):
        proof_len = len(field["proof"])
        total_nodes += proof_len
    print(f"   Proof: {proof_len} nodi")

    print(f"📈 Totale attributi rivelati: {len(revealed_fields)}")
    print(f"📈 Totale nodi nelle proof: {total_nodes}")
    return total_nodes

def timed(label, func, *args, **kwargs):
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    duration_ms = (end - start) * 1000
    print(f"- {label}: {duration_ms:.2f} ms")
    return result, duration_ms


if __name__ == "__main__":
    with open("nonce.txt") as f:
        nonce = f.read().strip()

    with open("package_to_verify.json") as f:
        package = json.load(f)

    revealed_fields = package["revealed_fields"]
    root = package["merkle_root"]
    signature_root = package["signature_root"]
    signed_nonce = package["signed_nonce"]
    rennes_cert = package["certificate_rennes"]
    student_pubkey_path = "studente.pub.pem"

    get_package_size()
    get_revealed_data_size(revealed_fields)

    _, sig_root_time = timed(" Tempo firma root", verify_signature_on_root, root, signature_root, rennes_cert)
    _, revocation_time = timed(" Tempo controllo revoca", check_revocation, root)
    _, nonce_time = timed(" Tempo firma nonce", verify_signed_nonce, nonce, signed_nonce, student_pubkey_path)
    analyze_merkle_proofs(revealed_fields)