import sys
from random import randint

from quanta import *
from mine import *

@p2p.on_connect
def handle_connect(peer):
    print(peer.__str__())

if __name__ == "__main__":
    try:
        _mining = "-mine" in sys.argv
        if _mining:
            miner = Miner(graph, p2p, True)
            miner.start(randint(0,1000000))
        p2p.run()
    finally:
        if _mining:
            miner.stop()
        p2p.shutdown()