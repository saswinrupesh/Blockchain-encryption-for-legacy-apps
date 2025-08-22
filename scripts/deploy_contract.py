# scripts/deploy_contract.py

import json
import os
from web3 import Web3
from solcx import compile_standard, install_solc

# Install Solidity compiler version (only first time needed)
install_solc("0.8.0")

# Connect to Ganache
WEB3_PROVIDER = os.getenv("WEB3_PROVIDER", "http://127.0.0.1:7545")
OWNER_ADDRESS = os.getenv("OWNER_ADDRESS")
OWNER_PRIVATE_KEY = os.getenv("OWNER_PRIVATE_KEY")

if not OWNER_ADDRESS or not OWNER_PRIVATE_KEY:
    raise Exception("Please set OWNER_ADDRESS and OWNER_PRIVATE_KEY in .env")

w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
chain_id = 1337  # Ganache default

# Load Solidity contract
with open("contracts/LegacyData.sol", "r") as file:
    legacy_contract_source = file.read()

# Compile contract
compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"LegacyData.sol": {"content": legacy_contract_source}},
        "settings": {
            "outputSelection": {"*": {"*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]}}
        },
    },
    solc_version="0.8.0",
)

# Extract ABI and Bytecode
abi = compiled_sol["contracts"]["LegacyData.sol"]["LegacyData"]["abi"]
bytecode = compiled_sol["contracts"]["LegacyData.sol"]["LegacyData"]["evm"]["bytecode"]["object"]

# Save ABI for middleware use
with open("contracts/LegacyData_abi.json", "w") as f:
    json.dump(abi, f)

# Deploy contract
LegacyData = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(OWNER_ADDRESS)

transaction = LegacyData.constructor().build_transaction(
    {
        "from": OWNER_ADDRESS,
        "nonce": nonce,
        "gas": 3000000,
        "gasPrice": w3.to_wei("20", "gwei"),
        "chainId": chain_id,
    }
)

signed_txn = w3.eth.account.sign_transaction(transaction, private_key=OWNER_PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print(f"✅ Contract deployed at {tx_receipt.contractAddress}")

# Save deployed contract address for reference
with open("contracts/deployed_address.txt", "w") as f:
    f.write(tx_receipt.contractAddress)
