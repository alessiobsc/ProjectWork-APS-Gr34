import os
import base64

def generate_nonce(length=16, filename="nonce.txt"):
    """
    Genera un nonce randomico, lo salva in base64 su file e lo ritorna.
    """
    nonce = base64.b64encode(os.urandom(length)).decode("utf-8")
    
    with open(filename, "w") as f:
        f.write(nonce)

    print(f"✅ Nonce generato e salvato in '{filename}': {nonce}")
    return nonce

generate_nonce(filename="nonce.txt")