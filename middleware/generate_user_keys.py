from crypto_utils import make_rsa_keypair, save_private_key_pem, save_public_key_pem

users = [
    ("owner", b"ownerpass"),
    ("manager", b"managerpass"),
]

for name, pwd in users:
    priv, pub = make_rsa_keypair()
    save_private_key_pem(priv, f"{name}_private.pem", password=pwd)
    save_public_key_pem(pub, f"{name}_public.pem")
    print(f"Generated RSA keys for {name}")
