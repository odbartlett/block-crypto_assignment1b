from typing import List, Optional
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from script import Script, sha256_hash
from transaction import Input, Output, Transaction

"""
Wallet functionality for building and signing transactions.
"""


def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    """
    Build and sign a transaction with the given inputs and outputs.

    This creates P2PKH unlocking scripts (scriptSig) for each input.
    Returns None if impossible to build a valid transaction.
    Does not verify that inputs are unspent.

    Validation checks:
    - Inputs and outputs must not be empty
    - All inputs must be spendable by the signing key (pub_key_hash matches)
    - Input values must equal output values
    - No duplicate inputs (same txid)

    Steps:
    1. Validate inputs and outputs
    2. Check that the signing key can spend all inputs
    3. Create an unsigned transaction (empty scriptSigs)
    4. Sign the transaction data
    5. Create scriptSig for each input with signature and public key
    6. Return the signed transaction
    """
    # TODO: Implement build_transaction
    # Hint: Use Script.p2pkh_unlocking_script(signature, pub_key) for scriptSig

    # Run non-empty checks
    if len(inputs) == 0 or len(outputs) == 0:
        return None
    
    # Get pk and its hash
    pub_key_bytes = signing_key.verify_key.encode()
    pub_key = pub_key_bytes.hex()
    pub_key_hash = sha256_hash(pub_key_bytes).hex()

    # Validate inputs for no dupes, all are spendable, and compute total input value
    seen_txids = set()
    total_input_value = 0

    for i in inputs:
        if i.tx_hash in seen_txids:
            return None
        seen_txids.add(i.tx_hash)

        output = i.output
        script_pub_key = output.script_pubkey

        elements = script_pub_key.elements
        expected_hash = elements[2]
        if expected_hash != pub_key_hash:
            return None
        
        total_input_value += output.value
    
    # Check that input values equal output values
    total_output_value = sum(o.value for o in outputs)
    if total_input_value != total_output_value:
        return None
    
    # Create unsigned transaction with empty scriptSigs
    unsigned_inputs = []
    for i in inputs:
        unsigned_inputs.append(Input(i.output, i.tx_hash, Script([])))
    tx = Transaction(unsigned_inputs, outputs)

    # Sign the transaction data
    tx_data = tx.bytes_to_sign()
    tx_data_bytes = bytes.fromhex(tx_data)

    signature_bytes = signing_key.sign(tx_data_bytes).signature
    signature = signature_bytes.hex()

    # Create scriptSig for each input and attach it
    for i in tx.inputs:
        i.script_sig = Script.p2pkh_unlocking_script(signature, pub_key)

    # Recompute hash after adding each input's script_sig
    tx.tx_hash = tx.get_hash()

    return tx