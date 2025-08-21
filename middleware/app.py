import os, sqlite3
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from crypto_utils import (
    aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt,
    load_public_key_pem, load_private_key_pem, sha256b, b64e, b64d
)
from blockchain import (
    register_data, set_permission, set_encrypted_key, get_encrypted_key
)
from web3 import Web3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, secrets

load_dotenv()
DB_PATH = os.getenv("SQLITE_PATH", "../legacy/legacy.db")
OWNER_ADDRESS = os.getenv("OWNER_ADDRESS")
SECRET_KEY_B64 = os.getenv("SECRET_KEY_B64")

if not SECRET_KEY_B64:
    # Generate one-time secret if not provided (dev only)
    SECRET_KEY_B64 = base64.b64encode(secrets.token_bytes(32)).decode()

SERVER_KEK = base64.b64decode(SECRET_KEY_B64)  # 32 bytes

app = Flask(__name__)

def seal_server_secret(plaintext):
    """Encrypt small secrets (AES content keys) with server-side KEK (AES-GCM)."""
    aes = AESGCM(SERVER_KEK)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct

def open_server_secret(nonce, ciphertext):
    aes = AESGCM(SERVER_KEK)
    return aes.decrypt(nonce, ciphertext, None)

@app.post('/store')
def store():
    body = request.get_json(force=True)
    plaintext = body['plaintext'].encode()
    data_id = body['data_id']
    allowed_users = body.get('allowed_users', [])

    aes_key, nonce, ciphertext = aes_encrypt(plaintext)

    plaintext_hash = sha256b(plaintext)  # 32 bytes
    keccak_hash = Web3.keccak(plaintext).hex()

    data_id_bytes32 = sha256b(data_id.encode())  # 32 bytes

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, data_id TEXT, nonce BLOB, ciphertext BLOB)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS aes_keys (data_id TEXT PRIMARY KEY, key_nonce BLOB, key_ciphertext BLOB)"
    )
    cur.execute(
        "INSERT INTO records (data_id, nonce, ciphertext) VALUES (?, ?, ?)",
        (data_id, nonce, ciphertext)
    )
    record_id = cur.lastrowid

    k_nonce, k_ct = seal_server_secret(aes_key)
    cur.execute("INSERT OR REPLACE INTO aes_keys (data_id, key_nonce, key_ciphertext) VALUES (?, ?, ?)",
                (data_id, k_nonce, k_ct))
    conn.commit()
    conn.close()

    register_data(data_id_bytes32, plaintext_hash)

    for u in allowed_users:
        addr = u['address']
        pub_path = u['public_key_pem']
        pub = load_public_key_pem(pub_path)
        enc_key = rsa_encrypt(pub, aes_key)  # bytes
        enc_key_b64 = b64e(enc_key)
        set_permission(data_id_bytes32, addr, True)
        set_encrypted_key(data_id_bytes32, addr, enc_key_b64)

    return jsonify({
        'record_id': record_id,
        'data_id': data_id,
        'data_id_hash_hex': sha256b(data_id.encode()).hex(),
        'plaintext_hash_sha256_hex': plaintext_hash.hex(),
        'plaintext_hash_keccak_hex': keccak_hash
    })

@app.post('/grant')
def grant():
    body = request.get_json(force=True)
    data_id = body['data_id']
    user_addr = body['user_address']
    pub_path = body['public_key_pem']

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT key_nonce, key_ciphertext FROM aes_keys WHERE data_id=?", (data_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'AES key not found for this data_id. Store first.'}), 404

    key_nonce, key_ct = row
    aes_key = open_server_secret(key_nonce, key_ct)

    pub = load_public_key_pem(pub_path)
    enc_key = rsa_encrypt(pub, aes_key)
    enc_key_b64 = b64e(enc_key)

    data_id_bytes32 = sha256b(data_id.encode())
    set_permission(data_id_bytes32, user_addr, True)
    set_encrypted_key(data_id_bytes32, user_addr, enc_key_b64)

    return jsonify({'status': 'granted', 'data_id': data_id, 'user_address': user_addr})

@app.post('/retrieve')
def retrieve():
    body = request.get_json(force=True)
    record_id = int(body['record_id'])
    data_id = body['data_id']
    caller_address = body['caller_address']
    priv_path = body['private_key_pem']
    priv_pwd = body.get('private_key_password')
    pwd_bytes = priv_pwd.encode() if priv_pwd else None

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT nonce, ciphertext FROM records WHERE id=? AND data_id=?", (record_id, data_id))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'record not found'}), 404
    nonce, ciphertext = row

    data_id_bytes32 = sha256b(data_id.encode())
    enc_key_b64 = get_encrypted_key(data_id_bytes32, caller_address)
    if not enc_key_b64:
        return jsonify({'error': 'no encrypted key set for this user'}), 403

    priv = load_private_key_pem(priv_path, password=pwd_bytes)
    aes_key = rsa_decrypt(priv, b64d(enc_key_b64))

    plaintext = aes_decrypt(aes_key, nonce, ciphertext)

    return jsonify({'plaintext': plaintext.decode(errors='ignore')})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
