from cryptography.fernet import Fernet
import json, hashlib, base64, os, subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from utils.validate_credential import validate_credential
from pathlib import Path

def extract_data_from_credential(credential, field_order):
    def get_value(path, data):
        parts = path.split('.')
        current = data
        for i, part in enumerate(parts):
            if '[i]' in part:
                key = part.split('[')[0]
                if key not in current:
                    return []
                subpath = '.'.join(parts[i+1:])
                result = []
                for idx, item in enumerate(current[key]):
                    if isinstance(item, dict):
                        val = get_value(subpath, item)
                        if isinstance(val, list):
                            result.extend([f"{part.replace('[i]', f'[{idx}]')}.{p}" for p in val])
                        else:
                            result.append(f"{part.replace('[i]', f'[{idx}]')}.{subpath}:{val}")
                    else:
                        # lista di stringhe o valori semplici
                        result.append(f"{part.replace('[i]', f'[{idx}]')}:{item}")
                return result
            else:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return f"{path}:<invalid>"
        return current if isinstance(current, str) else str(current)

    result = []
    for path in field_order:
        value = get_value(path, credential)
        if isinstance(value, list):
            result.extend(value)
        else:
            result.append(f"{path}:{value}")
    return result


def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def build_merkle_tree(data_list, salt):
    leaves = [sha256(salt + ":" + data) for data in data_list]
    tree = [leaves]  # Start with leaf level

    while len(tree[-1]) > 1:
        current_level = tree[-1]
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])  # Duplicate last leaf if odd

        next_level = [
            sha256(current_level[i] + current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]
        tree.append(next_level)

    return tree[-1][0], tree, leaves  # Return also leaves for verification


def fernet_encrypt(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode('utf-8'))

def fernet_decrypt(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode('utf-8')

def sign_merkle_root(merkle_root_hex, key_path):
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    root_bytes = bytes.fromhex(merkle_root_hex)
    signature = private_key.sign(
        root_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# CIFRATURA DELLA CREDENZIALE E DELLA ROOT, LO STUDENTE LA DECIFRERÀ
def hybrid_encrypt_payload(payload_dict, student_public_key_path):
    # Serializza il payload
    plaintext = json.dumps(payload_dict).encode()

    # Genera chiave simmetrica (Fernet usa AES con HMAC)
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    ciphertext = fernet.encrypt(plaintext)

    # Cifra la chiave AES con RSA-OAEP
    with open(student_public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "encrypted_key": encrypted_key.hex(),
        "ciphertext": ciphertext.decode(),
        "encryption": "RSA-OAEP + Fernet-AES"
    }

# Revoca della credenziale se la firma del nonce non è valida
def revoke_root_on_chain(root_hash: str):
    try:
        result = subprocess.run(
            ["npx", "truffle", "exec", "scripts/revoke.js", root_hash, "--network", "development"],
            cwd="blockchain",
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            raise RuntimeError(f"Errore JS: {result.stderr or result.stdout}")
        
        output = result.stdout.strip().splitlines()[-1]

        if output.startswith("✅ Root revocata:"):
            print(output)
        else:
            raise ValueError(f"Output inatteso: {output}")
    except Exception as e:
        raise RuntimeError(f"Errore nella revoca della root: {e}")

# Main
if __name__ == "__main__":
    with open("credential.json") as f:
        credential = json.load(f)

    try:
        validate_credential(credential)
    except ValueError as e:
        print(str(e))  # Stampa gli errori di validazione
        exit(1) 

    field_order = credential["canonicalFieldOrder"]
    data_list = extract_data_from_credential(credential, field_order)
    credential_salt = base64.b64encode(os.urandom(16)).decode('utf-8')

    merkle_root, tree, leaves = build_merkle_tree(data_list, credential_salt)

    print("Merkle root:", merkle_root)
    for i, leaf in enumerate(data_list):
        print(f"Leaf {i}: {leaf}")

    target_index = 3 
    target_leaf = data_list[target_index]

    signature = sign_merkle_root(merkle_root, "rennes.key.pem")
    #print("Firma della root (HEX):")
    #print(binascii.hexlify(signature).decode())

    # Calcola il pacchetto da cifrare
    payload_to_encrypt = {
        "credential": credential,
        "merkle_root": merkle_root,
        "signature_root": signature.hex(),
        "issuer": "rennes.univ.fr",
        "salt": credential_salt,
        "issuer_certificate": Path("rennes.cert.pem").read_text()
    }

    
    encrypted = hybrid_encrypt_payload(payload_to_encrypt, "studente.pub.pem")

    # Salva il pacchetto completo cifrato
    with open("encrypted_package.json", "w") as f:
        json.dump(encrypted, f, indent=2)

    print("✅ Cifratura completata e salvata in 'encrypted_package.json'")

    # Gestione richiesta di revoca firmata da Salerno 
    request_path = "revocation_request.json"
    if os.path.exists(request_path):
        print(f"📥 Richiesta di revoca rilevata in {request_path}")
        with open(request_path) as f:
            request = json.load(f)

        payload = request["payload"]
        signature = base64.b64decode(request["signature"])
        message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

        # Carica chiave pubblica di Salerno
        with open("salerno.pub.pem", "rb") as f:
            salerno_pubkey = serialization.load_pem_public_key(f.read())

        # Verifica firma
        try:
            salerno_pubkey.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Firma della richiesta verificata. Revoca autorizzata.")

            root_to_revoke = payload["root_hash"]
            if not root_to_revoke.startswith("0x"):
                root_to_revoke = "0x" + root_to_revoke

            revoke_root_on_chain(root_to_revoke)

            print("✅ Revoca completata.")

        except Exception as e:
            print(f"❌ Firma NON valida: richiesta ignorata.\nErrore: {e}")
    else:
        print("✅ Nessuna richiesta di revoca trovata.")


