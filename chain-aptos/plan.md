## Aptos HTLC Source Chain Contract Plan

### Core Data Structures

**Order Structure (Hash = Unique ID)**
```
- user_address, resolver_address
- user_amount, resolver_amount  
- venue_address, venue_fee
- arbitrator_address, arbitrator_attention_fee, arbitrator_usage_fee
- secret_hash
- submission_deadline, resolver_action_deadline
```

**Contract State**
- `resolver_balances: Map<address, u64>` - Available balances per resolver
- `active_escrows: Map<order_hash, EscrowState>` - Active escrow tracking
- `order_nonces: Set<order_hash>` - Prevent replay attacks

**EscrowState**
```
- order: Order struct
- user_deposited: u64
- resolver_locked: u64
- creation_time: u64
- status: Active | Resolved
```

### Main Functions

**1. `deposit_resolver_balance(amount)`**
- Resolver deposits native tokens to build balance

**2. `withdraw_resolver_balance(amount)`** 
- Resolver withdraws available (non-locked) balance

**3. `create_escrow(order, user_sig, resolver_sig)`**
- Verify both signatures on order hash
- Check current time < submission_deadline
- Transfer user_amount from user to contract
- Lock resolver_amount from resolver balance
- Pay venue_fee to venue immediately  
- Pay arbitrator_attention_fee to arbitrator immediately
- Create escrow state

**4. `resolve_with_secret(order_hash, secret)`**
- Verify secret hashes to order.secret_hash
- Transfer user_amount + resolver_locked to resolver
- Mark escrow resolved

**5. `resolve_early_exit(order_hash, resolver_sig)`**
- Verify resolver signature on refund instruction
- Transfer user_amount + resolver_locked to user (penalty applied)
- Mark escrow resolved

**6. `resolve_with_arbitrator(order_hash, arbitrator_decision_sig)`**
- Verify arbitrator signature on resolution
- If success: transfer user_amount + (resolver_locked - arbitrator_usage_fee) to resolver, usage_fee to arbitrator
- If failure: transfer user_amount + resolver_locked to user
- Mark escrow resolved

**7. `resolve_mutual(order_hash, user_sig, resolver_sig, distribution)`**
- Verify both signatures on agreed distribution
- Execute custom fund distribution
- Mark escrow resolved

**8. `claim_timeout_refund(order_hash)`**
- Check current time > resolver_action_deadline
- Transfer user_amount + resolver_locked to user (penalty applied)
- Mark escrow resolved

### Balance Requirements
At escrow creation, resolver must have:
`resolver_amount + venue_fee + arbitrator_attention_fee` available

Plus constraint: `arbitrator_usage_fee <= resolver_amount`

### Security Considerations
- Signature verification for all signed operations
- Timestamp validation for deadlines
- Balance sufficiency checks
- Prevent double-resolution of escrows
- Order hash uniqueness (replay protection)

Does this capture the complete contract design?