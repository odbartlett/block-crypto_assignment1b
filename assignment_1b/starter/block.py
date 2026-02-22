import hashlib
from typing import Optional, List

from transaction import Transaction, DIFFICULTY
from merkle import build_merkle_tree

r"""
Block structure for the blockchain.

=== BLOCK HEADER ===

In Bitcoin, the block header contains:
- Version (4 bytes)
- Previous block hash (32 bytes)
- Merkle root (32 bytes)        <-- Hash of all transactions
- Timestamp (4 bytes)
- Difficulty target (4 bytes)
- Nonce (4 bytes)

Our simplified version contains:
- Previous block hash
- Merkle root of transactions
- Nonce

=== MERKLE ROOT ===

Instead of hashing all transaction bytes directly, we compute a Merkle root.
This allows efficient proofs that a transaction is in a block (SPV).

For transactions [A, B, C, D], the Merkle tree looks like:

                 Root (stored in header)
                /      \\
            H(AB)    H(CD)
            /  \      /  \
          H(A) H(B) H(C) H(D)

=== MULTIPLE TRANSACTIONS ===

1. The first transaction SHOULD be a coinbase (block reward) - optional
2. Subsequent transactions are regular transactions spending UTXOs
3. Transactions are processed in order - earlier transactions in the block
   can create UTXOs that later transactions spend
"""


class Block:
    """
    A block on a blockchain. Prev is a string that contains the hex-encoded hash
    of the previous block. Contains a list of transactions.
    """

    def __init__(self, prev: str, txs: List[Transaction], nonce: Optional[str]):
        self.txs = txs
        self.nonce = nonce
        self.prev = prev

    def get_merkle_root(self) -> str:
        """Compute the Merkle root of all transactions in the block."""
        tx_hashes = [tx.tx_hash for tx in self.txs]
        return build_merkle_tree(tx_hashes)

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        # TODO: Implement mining
        # Hint: Increment nonce until hash() returns a value <= DIFFICULTY
        nonce = 0
        while True:
            # Store nonce as 8-byte big-endian hex string (matches test reference)
            self.nonce = nonce.to_bytes(8, byteorder="big", signed=False).hex()
            if int(self.hash(), 16) <= DIFFICULTY:
                break
            nonce += 1

    # Hash the block header (prev + merkle_root + nonce)
    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.get_merkle_root()))
        m.update(bytes.fromhex(self.nonce))

        return m.hexdigest()
