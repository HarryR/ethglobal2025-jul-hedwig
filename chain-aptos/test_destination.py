# SPDX-License-Identifier: AGPL-3.0-only
from os import urandom
from random import randint
from time import time
from hashlib import sha256
import sys
import requests

def main():
    network = 'devnet'
    fill_url = f'http://localhost:7300/aptos/{network}'
    helper_url = f'http://localhost:7301/aptos/{network}'

    fill_health = requests.get(f'{fill_url}/health.fill').json()
    assert fill_health['status'] == 'healthy'
    print("✅ Fill daemon healthy")

    helper_health = requests.get(f'{helper_url}/health.helper').json()
    assert helper_health['status'] == 'healthy'
    print("✅ Helper daemon healthy")

    secret = urandom(32)
    secret_hex = f"0x{secret.hex()}"
    secret_hash = sha256(secret).digest()
    secret_hash_hex = f"0x{secret_hash.hex()}"
    user_address = f"0x{urandom(32).hex()}"
    deadline = int(time() + 7200)
    amount = randint(1000,10000)

    user_balance_before = requests.get(f'{helper_url}/balance/{user_address}').json()['balance']
    assert user_balance_before == 0

    fill_obj = {
        'secret_hash': secret_hash_hex,
        'user_address': user_address,
        'amount': amount,
        'deadline': deadline
    }
    print("Fill Request", fill_obj)
    fill_resp = requests.post(f'{fill_url}/fill', json=fill_obj).json()
    print("Fill Response", fill_resp)

    fill_tx = requests.get(f'{helper_url}/txwait/{fill_resp["transaction_hash"]}').json()
    print("Fill Tx", fill_tx)

    reveal_obj = {
        'secret': secret_hex,
    }
    print("Reveal Request", reveal_obj)
    reveal_resp = requests.post(f'{helper_url}/reveal', json=reveal_obj).json()
    print("Reveal Response", reveal_resp)

    reveal_tx = requests.get(f'{helper_url}/txwait/{reveal_resp["transaction_hash"]}').json()
    print("Reveal TX", reveal_tx)
    

if __name__ == "__main__":
    sys.exit(main())
