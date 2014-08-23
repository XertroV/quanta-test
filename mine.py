import threading
from quanta import *

''' genesis_template = b'{"coinbase":0,"nonce":', b',"parent_hash":0,"target":6901746346790563787434755862277025452451108972170386555162524223799294,"timestamp":0,"tx":null,"uncle_hash":null}'
nonce = 1901660

make_genesis = lambda n: genesis_template[0]+ bytes(str(n).encode()) + genesis_template[1]

while True:
    nonce += 1
    if nonce % 1000 == 0:
        print(nonce)
    if global_hash(make_genesis(nonce)) < a.target:
        break

print(make_genesis(nonce))
print(repr(make_genesis(nonce).decode('utf-8')))
print(QuantaBlock.from_json(make_genesis(nonce).decode('utf-8')).serialize()) '''

class Miner:

    def __init__(self, graph=None):
        self._graph = graph
        self._special_nonce = 1234567890

    def set_graph(self, graph):
        self._graph = graph

    def stop(self):
        self._stop = True
        self._mining_thread.join()

    def restart(self):
        self.stop()
        self.start(**self._mining_kwargs)

    def start(self, coinbase, tx=None, target=(DIFF_ONE // (256 ** 3) - 2)):
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

        smallest = DIFF_ONE
        def is_smaller(hash):
            nonlocal smallest
            if hash < smallest:
                smallest = hash
                print('New smallest:', smallest)

        nonce = 3056000  # normally start at 0
        target = candidate.target
        self._running = True
        while not self._stop:
            h = global_hash(serd_block_from_nonce(nonce))
            is_smaller(h)
            if h < target:
                candidate = QuantaBlock.from_json(serd_block_from_nonce(nonce).decode())
                break
            nonce += 1
            if nonce % 1000 == 0: print(nonce)
        if candidate.acceptable_work:
            self._graph.add_blocks([candidate])
        self._running = False


if __name__ == '__main__':
    try:
        m = Miner(graph)
        m.start(0)
        m._mining_thread.join()
    except KeyboardInterrupt:
        m.stop()
    print(graph.head.parent_hash)