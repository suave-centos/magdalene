import subprocess
import sys
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

CERT_PATH = "signer.crt"  # Trusted certificate

def verify_signature(script_path):
    sig_path = script_path + ".sig"
    if not os.path.exists(sig_path):
        sig_path = script_path + ".sig.b64"
        if not os.path.exists(sig_path):
            print(f"[ERROR] No signature found for {script_path}")
            return False

    # Load signature (supports raw or base64)
    with open(sig_path, "rb") as f:
        data = f.read()
    try:
        sig = base64.b64decode(data)
    except Exception:
        sig = data  # already binary

    # Load public cert
    with open(CERT_PATH, "rb") as f:
        cert_data = f.read()
    cert = load_pem_x509_certificate(cert_data)
    public_key = cert.public_key()

    # Compute script hash
    with open(script_path, "rb") as f:
        script_data = f.read()

    # Verify signature
    try:
        public_key.verify(
            sig,
            script_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("[OK] Signature verified against trusted certificate.")
        return True
    except Exception as e:
        print(f"[ERROR] Signature verification failed: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python check_and_deploy_cert.py <script.py>")
        sys.exit(1)

    script = sys.argv[1]
    if verify_signature(script):
        print(f"Executing {script} ...")
        os.system(f"python3 {script}")
    else:
        print("Aborting — invalid or missing signature.")
        sys.exit(2)

if __name__ == "__main__":
    main()
