from hashlib import sha256
from copy import deepcopy
from queue import PriorityQueue

import pycoin.ecdsa as ecdsa
from spore import Spore
from encodium import *



# Constants

DIFF_ONE = MAX_32_BYTE_INT = 256 ** 32 - 1
MAX_8_BYTE_INT = 256 ** 8 - 1

FEE_CONSTANT = 10000  # 8000000  # Arbitrary-ish

# Exceptions

InvalidBlockException = BlockNotFoundException = Exception

# Structs

class Integer32Bytes(Encodium):
    class Definition(Encodium.Definition):
        _encodium_type = int

        def check_value(self, value):
            return 0 <= value < MAX_32_BYTE_INT

ECPoint = Target = Hash = Integer32Bytes

class Integer8Bytes(Encodium):
    class Definition(Encodium.Definition):
        _encodium_type = int

        def check_value(self, value):
            return 0 <= value < MAX_8_BYTE_INT

MoneyAmount = Timestamp = Nonce = Integer8Bytes

# State

class State:
    """ Super simple state device.
    Only functions are to add or subtract coins, and no checking is involved.
    All accounts are of 0 balance to begin with.
    """
    def __init__(self):
        self._state = {}

    def get(self, pub_x):
        return 0 if pub_x not in self._state else self._state[pub_x]

    def modify_balance(self, pub_x, value):
        self._state[pub_x] = self.get(pub_x) + value

# Graph Datastructs

class Orphanage:
    """ An Orphanage holds orphans.
    It acts as a priority queue, through put(), get(), etc. This is sorted by sigmadiff.
    For membership it acts as a set.
    """
    def __init__(self):
        self._priority_queue = PriorityQueue()
        self._set = set()
        self._removed = set()

    def __contains__(self, item):
        return False if item in self._removed else item in self._set

    def remove(self, block):
        if block not in self._set or block in self._removed:
            raise BlockNotFoundException()
        self._set.remove(block)
        self._removed.add(block)

    def _put_block(self, block):
        self._priority_queue.put((block.sigmadiff, block))

    def put(self, block):
        self._put_block(block)
        self._set.add(block)
        if block in self._removed:
            self._removed.remove(block)

    def _get_next_block(self):
        sigmadiff, block = self._priority_queue.get()
        while block in self._removed:
            sigmadiff, block = self._priority_queue.get()
        return sigmadiff, block

    def get(self):
        _, block = self._get_next_block()
        self._set.remove(block)
        return block

    def visit(self):
        sigmadiff, block = self._get_next_block()
        self._put_block(block)
        return block


# Graph Variables

class Graph:
    def __init__(self, root):
        self.root = root
        self.head = self.root
        self.orphans = Orphanage()
        self.all_nodes = {self.root}
        self.state = State()
        self.block_index = {self.root.hash: self.root}
        self.apply_to_state(self.root)

    def _back_up_state(self):
        self.backup_state = deepcopy(self.state)

    def _restore_backed_up_state(self):
        self.state = self.backup_state

    def has_block(self, block_hash):
        return block_hash in self.block_index

    def get_block(self, block_hash):
        return self.block_index[block_hash]

    def add_blocks(self, blocks):
        rejects = []
        self._back_up_state()
        try:
            for block in blocks:
                r = self._add_block(block)
                if r is not None:
                    rejects.append(r)
            if rejects != blocks:
                self.add_blocks(rejects)
        except Exception as e:
            self._restore_backed_up_state()

    def _add_block(self, block):
        """
        :param block: QuantaBlock instance
        :return: None on success, block if parent missing
        """
        if self.has_block(block.hash): return None
        if not block.acceptable_work: raise InvalidBlockException('Unacceptable work')
        if not self.has_block(block.parent_hash) or (block.uncle_hash is not None and not self.has_block(block.uncle_hash)):
            return block
        block.set_parent(self.block_index[block.parent_hash])
        if block.uncle_hash is not None: block.set_uncle(self.block_index[block.uncle_hash])
        if self.better_than_head(block):
            self.reorganize_to(block)
        else:
            self.orphans.put((block.sigmadiff, block))
        self.all_nodes.add(block)
        self.block_index[block.hash] = block
        return None

    def reorganize_to(self, block):
        print('reorg from %064x\nto         %064x\n' % (self.head.hash, block.hash))
        pivot = self.find_pivot(self.head, block)
        self.mass_unapply(Graph.order_from(pivot, self.head)[1:])
        self.mass_apply(Graph.order_from(pivot, block)[1:])
        self.head = block

    # Coin & State methods

    def valid_for_state(self, block):
        if block.tx == None: return True
        return self.state.get(block.tx.signature.pub_x) >= block.tx.value

    def apply_to_state(self, block):
        assert self.valid_for_state(block)
        self._modify_state(block, 1)

    def unapply_to_state(self, block):
        self._modify_state(block, -1)

    def _modify_state(self, block, direction):
        assert direction in [-1, 1]
        if block.tx is not None:
            self.state.modify_balance(block.tx.recipient, direction * block.tx.value)
            self.state.modify_balance(block.tx.signature.pub_x, -1 * direction * block.tx.value)
        self.state.modify_balance(block.coinbase, direction * block.coins_generated)

    def mass_unapply(self, path):
        for block in path[::-1]:
            self.unapply_to_state(block)
            self.orphans.put((block.sigmadiff, block))

    def mass_apply(self, path):
        for block in path:
            self.apply_to_state(block)
            if block in self.orphans: self.orphans.remove(block)

    def better_than_head(self, block):
        return block.sigmadiff > self.head.sigmadiff

    # Static Methods

    @staticmethod
    def order_from(early_node, late_node, carry=None):
        carry = [] if carry is None else carry
        if early_node == late_node:
            return [late_node]
        if late_node.parent_hash == 0:
            raise Exception('Root block encountered unexpectedly while ordering graph')
        main_path = exclude_from(Graph.order_from(early_node, late_node.parent), carry)
        aux_path = exclude_from(Graph.order_from(early_node, late_node.uncle), carry + main_path) if late_node.uncle is not None else []
        return main_path + aux_path + [late_node]

    @staticmethod
    def find_pivot(b1, b2):
        # conjecture: rewinding back to the lowest common parent in the primary chain (chain made of pri parents) is sufficient
        for past_block in b1.primary_chain:
            if past_block in b2.primary_chain:
                return past_block
        return None  # should probably not return None but do something else useful

# Associated Structures

class Signature(Encodium):
    r = ECPoint.Definition()
    s = ECPoint.Definition()
    pub_x = ECPoint.Definition()
    pub_y = ECPoint.Definition()
    msg_hash = Hash.Definition()

    def check(s, changed_attributes):
        assert valid_secp256k1_signature(s.pub_x, s.pub_y, s.msg_hash, s.r, s.s)

    @classmethod
    def from_secret_exponent_and_msg(cls, secret_exponent, msg):
        msg_hash = global_hash(msg)
        r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, msg_hash)
        x, y = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
        return Signature(pub_x=x, pub_y=y, r=r, s=s, msg_hash=msg_hash)


class Transaction(Encodium):
    value = MoneyAmount.Definition()
    recipient = ECPoint.Definition()
    signature = Signature.Definition()


# Block structure

class QuantaBlock(Encodium):
    parent_hash = Hash.Definition()
    uncle_hash = Hash.Definition(optional=True)
    target = Target.Definition()
    tx = Transaction.Definition(optional=True)
    coinbase = ECPoint.Definition()
    timestamp = Timestamp.Definition()
    nonce = Nonce.Definition()

    def __init__(self, *args, **kwargs):
        self._sigmadiff = None
        self._primary_chain = None
        self.parent = None
        self.uncle = None
        super().__init__(*args, **kwargs)

    def __hash__(self):
        return self.hash

    def check(s, changed_attributes):
        assert s.target < (DIFF_ONE // (256 ** 2))  # this is somewhat implied through the below
        assert s.coins_generated >= 0  # coins_generated and the assoc. fee can implicitly set an upper bound on the target

    # Graph

    def set_parent(self, parent):
        assert parent.hash == self.parent_hash
        self.parent = parent

    def set_uncle(self, uncle):
        if uncle == None:
            return
        assert uncle.hash == self.uncle_hash
        self.uncle = uncle

    # Properties

    @property
    def primary_chain(self):
        if self._primary_chain == None:
            if self.parent_hash == 0:
                self._primary_chain = [self]
            else:
                self._primary_chain = [self] + self.parent.primary_chain
        return self._primary_chain

    @property
    def hash(self):
        return hash_block(self)

    @property
    def sigmadiff(self):
        if self._sigmadiff == None:
            self._sigmadiff = sum(map(target_to_diff, [i.target for i in Graph.order_from(graph.root, self)]))
        return self._sigmadiff

    @property
    def coins_generated(self):
        return DIFF_ONE // self.target - storage_fee(self)

    @property
    def acceptable_work(s):
        return s.hash < s.target


# Helpers

def is_32_bytes(i):
    return 0 <= i < 256 ** 32

def is_4_bytes(i):
    return 0 <= i < 256 ** 4

def all_true(f, l):
    return False not in map(f, l)

def global_hash(msg: bytes):
    return int.from_bytes(sha256(msg).digest(), 'big')


def hash_block(block: QuantaBlock):
    return global_hash(bytes(block.serialize()))


def target_to_diff(target):
    return DIFF_ONE // target


def exclude_from(a, b):  # operates on paths
    return [i for i in a if i not in b]


# Crypto Helpers

def valid_secp256k1_signature(x, y, msg, r, s):
    return ecdsa.verify(ecdsa.generator_secp256k1, (x, y), global_hash(msg), (r, s))


# Network-y functions

def storage_fee(block):
    return len(block.to_json()) * FEE_CONSTANT


# P2P Setup

port = 2281
seeds = [('198.199.102.43', port-1  ), ('127.0.0.1', port)]
p2p = Spore(seeds, ('0.0.0.0', port))

# P2P Messages

BLOCK_ANNOUNCE = 'block_announce'
BLOCK_REQUEST = 'block_request'
BLOCK_PROVIDE = 'block_provide'
INV_REQUEST = 'inv_request'
INV_PROVIDE = 'inv_provide'
INFO_REQUEST = 'info_request'
INFO_PROVIDE = 'info_provide'

# Message Containers

class BlockAnnounce(Encodium):
    block = QuantaBlock.Definition()

class BlockRequest(Encodium):
    hashes = List.Definition(Hash.Definition())  # blocks we're requesting

class BlockProvide(Encodium):
    blocks = List.Definition(QuantaBlock.Definition())

class InvRequest(Encodium):
    pass

class InvProvide(Encodium):
    inv_list = List.Definition(Hash.Definition())

class InfoRequest(Encodium):
    pass

class InfoProvide(Encodium):
    top_block = Hash.Definition()

# Message Handlers

@p2p.on_message(BLOCK_ANNOUNCE, BlockAnnounce.from_json)
def handle_block_announce(peer, announcement):
    graph.add_blocks([announcement.block])
    p2p.broadcast(BLOCK_ANNOUNCE, announcement)

@p2p.on_message(BLOCK_REQUEST, BlockRequest.from_json)
def handle_block_request(peer, request):
    peer.send(BLOCK_PROVIDE, BlockProvide(blocks=[graph.get_block(h) for h in request.hashes]))

@p2p.on_message(BLOCK_PROVIDE, BlockProvide.from_json)
def handle_block_provide(peer, provided):
    graph.add_blocks(provided.blocks)

@p2p.on_message(INV_REQUEST, InvRequest.from_json)
def handle_inv_request(peer, request):
    peer.send(INV_PROVIDE, InvProvide(inv_list=[b.hash for b in graph.all_nodes]))

@p2p.on_message(INV_PROVIDE, InvProvide.from_json)
def handle_inv_provide(peer, provided):
    to_request = [i for i in provided.inv_list if i not in graph.all_nodes]
    peer.send(BLOCK_REQUEST, BlockRequest(hashes=to_request))

@p2p.on_message(INFO_REQUEST, InfoRequest.from_json)
def handle_info_request(peer, request):
    peer.send(INFO_PROVIDE, InfoProvide(top_block=graph.head.hash))

@p2p.on_message(INFO_PROVIDE, InfoProvide.from_json)
def handle_info_provide(peer, provided):
    if provided.top_block not in graph.all_nodes:
        peer.send(INV_REQUEST, InvRequest())

@p2p.on_connect
def handle_connect(peer):
    peer.send(INFO_REQUEST, InfoRequest())

# Create graph

genesis_block = QuantaBlock(parent_hash=0, target=(DIFF_ONE // (256 ** 3) - 1), coinbase=0, timestamp=0, nonce=1901667)
graph = Graph(genesis_block)
