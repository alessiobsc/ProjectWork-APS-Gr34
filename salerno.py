import json, subprocess, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from datetime import datetime, timezone
from rennes import sha256
from utils.generate_revocation_request import generate_revocation_request

def verify_merkle_proof(leaf_value, leaf_index, proof, expected_root, salt):
    current_hash = sha256(salt + ":" + leaf_value)

    for sibling_hash in proof:
        if leaf_index % 2 == 0:
            current_hash = sha256(current_hash + sibling_hash)
        else:
            current_hash = sha256(sibling_hash + current_hash)
        leaf_index //= 2

    return current_hash == expected_root

# Firma root 
def verify_signature_on_root(merkle_root_hex, signature_hex, cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    public_key = cert.public_key()

    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            bytes.fromhex(merkle_root_hex),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"❌ Firma della root NON valida:", e)
        return False

# Firma del nonce 
def verify_signed_nonce(nonce, signed_nonce_hex, student_pubkey_path):
    with open(student_pubkey_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            bytes.fromhex(signed_nonce_hex),
            nonce.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        #print("❌ Firma del nonce NON valida:", e)
        return False
    
# Verifica scadenza certificato
def is_cert_valid(cert_pem: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    print(f"📅 Certificato valido da {not_before} a {not_after}")
    
    if now < not_before or now > not_after:
        print("⛔ Certificato SCADUTO o NON ancora valido.")
        return False
    else:
        print("✅ Certificato attualmente valido.")
        return True


# Verifica della revoca
def check_revocation(root_hash: str) -> bool:
    try:
        result = subprocess.run(
            ["npx", "truffle", "exec", "scripts/check.js", root_hash, "--network", "development"],
            cwd="blockchain",
            capture_output=True, text=True, timeout=10
        )
    
        if result.returncode != 0:
            raise RuntimeError(f"Errore JS: {result.stderr or result.stdout}")
        
        output = result.stdout.strip().splitlines()[-1]
        if output == "revoked":
            return True
        elif output == "valid":
            return False
        else:
            raise ValueError(f"Output inatteso: {output}")
    except Exception as e:
        raise RuntimeError(f"Errore controllo revoca: {e}")
    
# Main
if __name__ == "__main__":
    # Carica pacchetto ricevuto
    with open("package_to_verify.json") as f:
        package = json.load(f)

    revealed_fields = package["revealed_fields"]
    root = package["merkle_root"]
    signature_root = package["signature_root"]
    signed_nonce = package["signed_nonce"]
    rennes_cert = package["certificate_rennes"]
    salt = package["salt"]

    # Carica nonce originale inviato
    with open("nonce.txt") as f:
        nonce = f.read().strip()
    
    # Verifica validità del certificato Rennes
    if not is_cert_valid(rennes_cert):
        print("⛔ Certificato di Rennes NON valido. Interrompo.")
        exit(1)

    start = time.time()
    all_valid = all(
        verify_merkle_proof(field["value"], field["index"], field["proof"], root, salt)
        for field in revealed_fields
    )
    end = time.time()

    # Output finale solo se tutto è ok
    if all_valid:
        print(f"✅ Tutte le Merkle Proof sono valide -> {((end - start)*1000):.2f} ms")
    else:
        print("⛔ Almeno una Merkle Proof NON è valida.")
        exit(1)

    if verify_signature_on_root(root, signature_root, rennes_cert):
        print("✅ Firma della root verificata: emessa da Rennes.")
    else:
        print("❌ Firma NON valida sulla root")
        exit(1)

    # Verifica della revoca 
    try:
        if check_revocation(root):
            print("⛔ Credenziale REVOCATA su blockchain.")
            exit(1)
        else:
            print("✅ Credenziale NON revocata.")
    except Exception as e:
        print(f"⚠️ Errore durante la verifica della revoca: {e}")
        exit(1)

    student_pubkey_path = "studente.pub.pem"
    if verify_signed_nonce(nonce, signed_nonce, student_pubkey_path):
        print("✅ Firma del nonce valida -> identità dello studente confermata.")
    else:
        print("❌ Firma del nonce NON valida.")
        generate_revocation_request(
            root_hash=root if root.startswith("0x") else "0x" + root,
            reason="Firma del nonce non valida",
            private_key="salerno.key.pem"
        )
        print("📨 Richiesta inviata a Rennes per la revoca.")
        exit(1)
        

