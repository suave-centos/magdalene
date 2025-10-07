# Create a detached signature
openssl dgst -sha256 -sign signer.key -out cleanup.py.sig cleanup.py
