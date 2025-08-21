import json, os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
WEB3_HTTP = os.getenv("WEB3_HTTP")
OWNER_PRIVATE_KEY = os.getenv("OWNER_PRIVATE_KEY")
OWNER_ADDRESS = os.getenv("OWNER_ADDRESS")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

w3 = Web3(Web3.HTTPProvider(WEB3_HTTP))
assert w3.is_connected(), "Web3 not connected. Check Ganache."

with open("contract_abi.json", "r") as f:
    ABI = json.load(f)

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)

def _send_tx(func):
    nonce = w3.eth.get_transaction_count(OWNER_ADDRESS)
    tx = func.build_transaction({
        'from': OWNER_ADDRESS,
        'nonce': nonce,
        'gas': 1500000,
        'gasPrice': w3.to_wei('2', 'gwei')
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=OWNER_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def register_data(data_id_bytes32: bytes, data_hash_bytes32: bytes):
    return _send_tx(contract.functions.registerData(data_id_bytes32, data_hash_bytes32))

def set_permission(data_id_bytes32: bytes, user_address: str, allowed: bool):
    return _send_tx(contract.functions.setPermission(data_id_bytes32, Web3.to_checksum_address(user_address), allowed))

def set_encrypted_key(data_id_bytes32: bytes, user_address: str, encrypted_key_b64: str):
    return _send_tx(contract.functions.setEncryptedKey(data_id_bytes32, Web3.to_checksum_address(user_address), encrypted_key_b64))

def get_encrypted_key(data_id_bytes32: bytes, caller_private_key: str, caller_address: str) -> str:
    return contract.functions.getEncryptedKey(data_id_bytes32).call({'from': Web3.to_checksum_address(caller_address)})
