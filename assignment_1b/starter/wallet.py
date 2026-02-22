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
    # Hint: Use Script.p2pkh_unlocking_script(signature, pub_key) for scriptSig
    if not inputs or not outputs:
        return None

    pub_key = signing_key.verify_key.encode().hex()
    pub_key_hash = sha256_hash(signing_key.verify_key.encode()).hex()

    input_sum = 0
    seen_txids = set()
    for inp in inputs:
        if inp.tx_hash in seen_txids:
            return None
        seen_txids.add(inp.tx_hash)
        # Check that we can spend this input (pubkey hash matches)
        expected_hash = inp.output.script_pubkey.elements[2]
        if expected_hash != pub_key_hash:
            return None
        input_sum += inp.output.value

    output_sum = sum(o.value for o in outputs)
    if input_sum != output_sum:
        return None

    unsigned_inputs = [Input(inp.output, inp.tx_hash, Script([])) for inp in inputs]
    unsigned_tx = Transaction(unsigned_inputs, outputs)
    tx_data = bytes.fromhex(unsigned_tx.bytes_to_sign())
    signature = signing_key.sign(tx_data).signature.hex()

    signed_inputs = []
    for inp in inputs:
        script_sig = Script.p2pkh_unlocking_script(signature, pub_key)
        signed_inputs.append(Input(inp.output, inp.tx_hash, script_sig))
    return Transaction(signed_inputs, outputs)
