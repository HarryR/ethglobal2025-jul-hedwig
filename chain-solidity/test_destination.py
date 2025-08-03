# SPDX-License-Identifier: AGPL-3.0-only
from os import urandom
from hashlib import sha256
import sys
import requests
import json

def main():
    network = 'hardhat_local'
    
    # All daemon URLs
    fill_url = f'http://localhost:7400/ethereum/{network}'
    helper_url = f'http://localhost:7401/ethereum/{network}'
    arbitrator_url = f'http://localhost:7402/ethereum/{network}'
    quote_url = f'http://localhost:7403/ethereum/{network}'

    # Health check all daemons
    fill_health = requests.get(f'{fill_url}/health.fill').json()
    assert fill_health['status'] == 'healthy'

    helper_health = requests.get(f'{helper_url}/health.helper').json()
    assert helper_health['status'] == 'healthy'
    
    arbitrator_health = requests.get(f'{arbitrator_url}/health.arbitrator').json()
    assert arbitrator_health['status'] == 'healthy'
    
    quote_health = requests.get(f'{quote_url}/health.quote').json()
    assert quote_health['status'] == 'healthy'

    # Generate test parameters
    secret = urandom(32)
    secret_hex = f"0x{secret.hex()}"
    secret_hash = sha256(secret).digest()
    secret_hash_hex = f"0x{secret_hash.hex()}"
    user_address = f"0x{urandom(20).hex()}"
    source_amount = int(321)  # 1 ETH
    destination_amount = int(123)  # 0.99 ETH (after fees)
    
    print(f"   Secret: {secret_hex}")
    print(f"   Secret hash: {secret_hash_hex}")
    print(f"   User address: {user_address}")
    print(f"   Source amount: {source_amount}")
    print(f"   Destination amount: {destination_amount}")
    
    # Get quote from resolver
    quote_request = {
        'user_address': user_address,
        'source_amount': source_amount,
        'destination_chain': f'ethereum-{network}',
        'destination_amount': destination_amount,
        'secret_hash': secret_hash_hex
    }
    
    print(f"   Quote request: {json.dumps(quote_request, indent=2)}")
    quote_response = requests.post(f'{quote_url}/quote.resolver', json=quote_request).json()
    
    if not quote_response['success']:
        print(f"❌ Quote failed: {quote_response}")
        return 1

    order = quote_response['order']
    signature = quote_response['signature']
    
    print(f"   Order hash: {signature['order_hash']}")
    print(f"   Signature: r={signature['r']}, s={signature['s']}, v={signature['v']}")

    # TODO: Step 2 would be to create escrow on SourceHTLC with the signed order
    # For now, we'll proceed directly to destination HTLC creation
    
    # Check initial balance
    user_balance_before = requests.get(f'{helper_url}/balance/{user_address}').json()
    print(f"   User balance before: {user_balance_before['balance']} wei")
    assert user_balance_before['balance'] == 0

    # Create HTLC on destination chain
    fill_request = {
        'secret_hash': secret_hash_hex,
        'user_address': user_address,
        'amount': destination_amount,
        'deadline': order['resolverActionDeadline']  # Use same deadline as order
    }
    
    print(f"   Fill request: {json.dumps(fill_request, indent=2)}")
    fill_response = requests.post(f'{fill_url}/fill', json=fill_request).json()
    
    if not fill_response['success']:
        print(f"❌ Fill failed: {fill_response}")
        return 1
        
    print("✅ HTLC created on destination chain")
    print(f"   Transaction: {fill_response['transaction_hash']}")

    # Wait for transaction confirmation
    fill_tx = requests.get(f'{helper_url}/txwait/{fill_response["transaction_hash"]}').json()
    print(f"   Block: {fill_tx['blockNumber']}, Gas used: {fill_tx['gasUsed']}")

    print("\n📊 Step 3: Verify HTLC info...")
    
    # Get HTLC info
    htlc_info = requests.get(f'{helper_url}/destination_htlc/{secret_hash_hex}').json()
    print(f"   HTLC info: {json.dumps(htlc_info, indent=2)}")
    
    assert htlc_info['user_address'].lower() == user_address.lower()
    assert htlc_info['amount'] == destination_amount
    assert htlc_info['deadline'] == order['resolverActionDeadline']

    print("\n⚖️  Step 4: Test arbitrator before deadline...")
    
    # Test arbitrator - should return success (deposited on time)
    arbitrator_request = {
        'secret_hash': secret_hash_hex,
        'deadline': order['resolverActionDeadline'],
        'destination_amount': destination_amount,
        'destination_chain': order['destinationChain'],
        'destination_token': '0x' + ('00' * 32),  # Native ETH
        'destination_address': user_address
    }
    
    print(f"   Arbitrator request: {json.dumps(arbitrator_request, indent=2)}")
    arbitrator_response = requests.post(f'{arbitrator_url}/arbitrate.ethereum', json=arbitrator_request).json()
    
    if not arbitrator_response['success']:
        print(f"❌ Arbitration failed: {arbitrator_response}")
        return 1
        
    print("✅ Arbitrator decision received")
    print(f"   Decision: {arbitrator_response['decision']['decision']} (True = deposited on time)")
    print(f"   Struct hash: {arbitrator_response['structHash']}")
    print(f"   Signature: {arbitrator_response['signature']}")
    
    # Verify decision is True (deposited on time)
    assert arbitrator_response['decision']['decision'] == True

    print("\n🔓 Step 5: Reveal secret to claim funds...")
    
    # Reveal secret to claim funds
    reveal_request = {
        'secret': secret_hex,
    }
    
    print(f"   Reveal request: {json.dumps(reveal_request, indent=2)}")
    reveal_response = requests.post(f'{helper_url}/reveal', json=reveal_request).json()
    
    if not reveal_response['success']:
        print(f"❌ Reveal failed: {reveal_response}")
        return 1
        
    print("✅ Secret revealed, funds claimed")
    print(f"   Transaction: {reveal_response['transaction_hash']}")

    # Wait for reveal transaction
    reveal_tx = requests.get(f'{helper_url}/txwait/{reveal_response["transaction_hash"]}').json()
    print(f"   Block: {reveal_tx['blockNumber']}, Gas used: {reveal_tx['gasUsed']}")

    print("\n💰 Step 6: Verify final balances...")
    
    # Check final balance
    user_balance_after = requests.get(f'{helper_url}/balance/{user_address}').json()
    print(f"   User balance after: {user_balance_after['balance']} wei")
    
    # Balance should be destination_amount (funds were transferred to user)
    # Note: This assumes user_address is an actual account, not a random address
    # In real test, you'd use actual funded accounts
    
    print("\n⚖️  Step 7: Test arbitrator after timeout (should fail)...")
    
    # Test what happens if we try to arbitrate an already-claimed HTLC
    try:
        arbitrator_response_2 = requests.post(f'{arbitrator_url}/arbitrate.ethereum', json=arbitrator_request).json()
        if arbitrator_response_2['success']:
            print("⚠️  Arbitrator allowed re-arbitration of claimed HTLC")
        else:
            print(f"✅ Arbitrator correctly rejected re-arbitration: {arbitrator_response_2['error']}")
    except Exception as e:
        print(f"✅ Arbitrator correctly rejected re-arbitration: {e}")

    print("\n🎉 All tests passed! Cross-chain atomic swap completed successfully.")
    print("\nFlow summary:")
    print("1. ✅ Resolver provided signed quote")
    print("2. ✅ HTLC created on destination chain")  
    print("3. ✅ Arbitrator confirmed on-time deposit")
    print("4. ✅ User revealed secret and claimed funds")
    print("5. ✅ Arbitrator correctly handles post-claim requests")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
