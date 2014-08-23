import threading
from quanta import *


class Miner:

    def __init__(self, graph=None, p2p=None, run_forever=False):
        self._graph = graph
        self._special_nonce = 1234567890
        self._run_forever = run_forever
        self._p2p = p2p

    def set_graph(self, graph):
        self._graph = graph

    def stop(self):
        self._stop = True
        self._mining_thread.join()

    def restart(self):
        self.stop()
        self.start(**self._mining_kwargs)

    def start(self, coinbase, tx=None, target=(DIFF_ONE // (64 * 256 ** 2))):
        self._mining_kwargs = {'coinbase': coinbase, 'tx': tx, 'target': target}
        candidate = QuantaBlock(parent_hash=self._graph.head.hash, timestamp=0, nonce=self._special_nonce, **self._mining_kwargs)
        if tx is not None:
            candidate.tx = tx
        self._stop = False
        self._mining_thread = threading.Thread(target=self._start_mining, args=[candidate])
        self._mining_thread.start()

    def _start_mining(self, candidate):

        m1, m2 = map(bytes,
                     candidate.serialize().split(
                         str(self._special_nonce).encode())
        )
        serd_block_from_nonce = lambda n: m1 + str(n).encode() + m2

        nonce = 3056000  # normally start at 0
        target = candidate.target
        self._running = True
        while not self._stop:
            h = global_hash(serd_block_from_nonce(nonce))
            if h < target:
                candidate = QuantaBlock.from_json(serd_block_from_nonce(nonce).decode())
                break
            nonce += 1
            if nonce % 100000 == 0: print(nonce)
        if candidate.acceptable_work:
            if self._graph: self._graph.add_blocks([candidate])
            if self._p2p: self._p2p.broadcast(BLOCK_ANNOUNCE, BlockAnnounce(block=candidate))
        self._running = False

        if self._run_forever and not self._stop:
            self.start(candidate.coinbase)


if __name__ == '__main__':
    try:
        m = Miner(graph)
        while True:
            m.start(0)
            m._mining_thread.join()
    except KeyboardInterrupt:
        m.stop()
    print(graph.head.parent_hash)