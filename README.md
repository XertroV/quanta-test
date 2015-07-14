# quanta-test
tiny demo chain (mostly nonfunctional) to demo an instant-confirmation blockchain.

the trick is to use a DAG of txs each with a PoW and prevblocks. a deterministic ordering algorithm is used to favour the head with the most work, so there is only a small set of transactions that are ever not in the main chain.
