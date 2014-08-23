from quanta import *
from mine import *

if __name__ == "__main__":
    try:
        miner = Miner(graph, True)
        miner.start(0)
        p2p.run()
    except KeyboardInterrupt:
        miner.stop()
        p2p.shutdown()