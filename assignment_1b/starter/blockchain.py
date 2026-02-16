from typing import List, Optional

from block import Block
from transaction import Transaction, Input

"""
Blockchain data structure - a chain of blocks with UTXO tracking.
"""


class Blockchain:
    """
    A blockchain. This class is provided for convenience only; the autograder
    will not call this class.
    """

    def __init__(self, chain: List[Block], utxos: List[str]):
        self.chain = chain
        self.utxos = utxos

    def append(self, block: Block) -> bool:
        """Append a block to the chain and update UTXOs for all its transactions."""
        self.chain.append(block)
        for tx in block.txs:
            for inp in tx.inputs:
                idx = self._output_index_for_input(inp)
                if idx is not None:
                    utxo_id = f"{inp.number}:{idx}"
                    if utxo_id in self.utxos:
                        self.utxos.remove(utxo_id)
            for i in range(len(tx.outputs)):
                self.utxos.append(f"{tx.number}:{i}")
        return True

    def _find_transaction(self, tx_number: str) -> Optional[Transaction]:
        """Find a transaction by its number in the chain."""
        for block in self.chain:
            for tx in block.txs:
                if tx.number == tx_number:
                    return tx
        return None

    def _output_index_for_input(self, inp: Input) -> Optional[int]:
        """Return the output index in the creating transaction for this input."""
        tx = self._find_transaction(inp.number)
        if tx is None:
            return None
        for i, out in enumerate(tx.outputs):
            if (out.value == inp.output.value and
                    out.script_pubkey.elements == inp.output.script_pubkey.elements):
                return i
        return None
