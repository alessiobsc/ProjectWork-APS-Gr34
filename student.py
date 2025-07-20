import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from rennes import (extract_data_from_credential, sha256, build_merkle_tree)
from salerno import (is_cert_valid, verify_signature_on_root)
from cryptography.fernet import Fernet

# DECIFRATURA
def hybrid_decrypt_package(encrypted_dict, student_private_key_path):
    # Decifra la chiave AES con la chiave privata RSA
    encrypted_key = bytes.fromhex(encrypted_dict["encrypted_key"])

    with open(student_private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decifra il contenuto con Fernet/AES
    fernet = Fernet(aes_key)
    decrypted_bytes = fernet.decrypt(encrypted_dict["ciphertext"].encode())
    decrypted_data = json.loads(decrypted_bytes.decode())

    return decrypted_data

def build_merkle_proof(data_list, leaf_index):
    leaves = [sha256(salt + ":" + data) for data in data_list]
    proof = []
    index = leaf_index
    level = leaves

    while len(level) > 1:
        if len(level) % 2 != 0:
            level.append(level[-1])  # se dispari, duplica ultimo nodo

        sibling_index = index + 1 if index % 2 == 0 else index - 1
        proof.append(level[sibling_index])
        index = index // 2

        level = [
            sha256(level[i] + level[i+1])
            for i in range(0, len(level), 2)
        ]

    return proof
# Firma nonce
def sign_nonce(nonce, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature = private_key.sign(
        nonce.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature.hex()

# Main
if __name__ == "__main__":
    with open("encrypted_package.json") as f:
        encrypted = json.load(f)

    cert_pem = Path("rennes.cert.pem").read_text()
    if not is_cert_valid(cert_pem):
        #print("❌ Il certificato dell’università è scaduto o non valido.")
        exit(1)

    decrypted = hybrid_decrypt_package(encrypted, "studente.key.pem")

    credential = decrypted["credential"]
    merkle_root = decrypted["merkle_root"]
    signature_root = decrypted["signature_root"]
    issuer = decrypted["issuer"]
    salt = decrypted["salt"]
    issuer_cert = decrypted["issuer_certificate"]

    # Verifica firma della root con chiave nel certificato incluso
    if not verify_signature_on_root(merkle_root, signature_root, issuer_cert):
        print("❌ Firma della root NON valida.")
        exit(1)

    # Costruisci data_list e Merkle Tree
    field_order = credential["canonicalFieldOrder"]
    data_list = extract_data_from_credential(credential, field_order)
    _, merkle_tree, _ = build_merkle_tree(data_list, salt)

    # Seleziona attributi da rivelare
    fields_to_reveal = []
    for i, value in enumerate(data_list):
        if value.startswith("student.matricola:") or value.startswith("esami_superati["):
            fields_to_reveal.append((i, value))

    # Costruisci le proof
    revealed_fields = []
    for index, value in fields_to_reveal:
        proof = build_merkle_proof(data_list, index)
        revealed_fields.append({
            "value": value,
            "index": index,
            "proof": proof
        })

    # Prima di firmare il nonce si deve lanciare lo script nonce_generator e poi lanciare questo script
    nonce = Path("nonce.txt").read_text().strip()
    signed_nonce = sign_nonce(nonce, "studente.key.pem")

    # Costruisci pacchetto
    package = {
        "revealed_fields": revealed_fields,
        "merkle_root": merkle_root,
        "signature_root": signature_root,
        "signed_nonce": signed_nonce,
        "issuer": issuer,
        "public_key_student": Path("studente.pub.pem").read_text(),
        "certificate_rennes": Path("rennes.cert.pem").read_text(),
        "salt": salt
    }

    # Salva il pacchetto da inviare a Salerno
    with open("package_to_verify.json", "w") as f:
        json.dump(package, f, indent=2)

    print("✅ Pacchetto con attributi rivelati generato in 'package_to_verify.json'")