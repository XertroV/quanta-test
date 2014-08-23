from quanta import *
from mine import *

@p2p.on_connect
def handle_connect(peer):
    print('Connected to', peer)

if __name__ == "__main__":
    try:
        miner = Miner(graph, p2p, True)
        miner.start(0)
        p2p.run()
    except KeyboardInterrupt:
        miner.stop()
        p2p.shutdown()