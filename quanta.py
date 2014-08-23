from hashlib import sha256
from copy import deepcopy

import pycoin.ecdsa as ecdsa
from spore import Spore
from encodium import *



# Constants

PUSHBLOCKS = 'pushblocks'
PULLBLOCKS = 'pullblocks'

DIFF_ONE = 2 ** 256 - 1

FEE_CONSTANT = 10000  # 8000000  # Arbitrary-ish


# State

class State:
    def __init__(self):
        self._state = {}

    def get(self, pub_x):
        return 0 if pub_x not in self._state else self._state[pub_x]

    def move_coins(self, pub_x, value):
        self._state[pub_x] = self.get(pub_x) + value


# Graph Variables

class Graph:
    def __init__(self):
        self.head = None  # for a block to be added (and become head), parent must be head and uncle must be in orphans
        self.root = None
        self.orphans = set()  # for a block to be added (that's not head), parent and uncle must be in orphans
        self.state = State()
        self.block_index = {}

    def set_root(self, root):
        if self.head == None: self.head = root
        self.root = root
        self._add_block(self.root, is_root=True)
        self.apply_to_state(self.root)

    def _back_up_state(self):
        self.backup_state = deepcopy(self.state)

    def _restore_backed_up_state(self):
        self.state = self.backup_state

    def have_block(self, block_hash):
        return block_hash in self.block_index

    def add_blocks(self, blocks):
        self._back_up_state()
        try:
            for block in blocks: self._add_block(block)
        except Exception as e:
            raise e
            self._restore_backed_up_state()

    def _add_block(self, block, is_root=False):
        if not is_root:
            if self.have_block(block.hash):
                return 'Already have block'
            if not self.have_block(block.parent_hash) or (block.uncle_hash is not None and not self.have_block(block.uncle_hash)):
                return 'Absent parent / uncle'
            block.set_parent(self.block_index[block.parent_hash])
            if block.uncle_hash is not None: block.set_uncle(block_index[block.uncle_hash])
            if self.better_than_head(block):
                self.reorganize_to(block)
            else:
                self.orphans.add(block)
        self.block_index[block.hash] = block

    def reorganize_to(self, block):
        print('reorg to', block.hash, 'from', self.head.hash)
        pivot = self.find_pivot(self.head, block)
        self.mass_unapply(Graph.order_from(pivot, self.head)[1:])
        self.mass_apply(Graph.order_from(pivot, block)[1:])
        self.head = block

    # Coin & State methods

    def valid_for_state(self, block):
        if block.tx == None: return True
        return self.state.get(block.tx.signature.pub_x) >= block.tx.value

    def apply_to_state(self, block):
        self.modify_state(block, 1)

    def unapply_to_state(self, block):
        self.modify_state(block, -1)

    def modify_state(self, block, direction):
        assert direction in [-1, 1]
        if block.tx is not None:
            self.state.move_coins(block.tx.recipient, direction * block.tx.value)
            self.state.move_coins(block.tx.signature.pub_x, -1 * direction * block.tx.value)
        self.state.move_coins(block.coinbase, direction * block.coins_generated)

    def mass_unapply(self, path):
        for block in path[::-1]:
            self.unapply_to_state(block)
            self.orphans.add(block)

    def mass_apply(self, path):
        for block in path:
            assert self.valid_for_state(block)
            self.apply_to_state(block)
            if block in self.orphans: self.orphans.remove(block)

    def better_than_head(self, block):
        return block.sigmadiff > self.head.sigmadiff

    # Static Methods

    @staticmethod
    def order_from(early_node, late_node, carry=None):
        if not carry: carry = []
        if early_node == late_node:
            return [late_node]
        if late_node.parent_hash == 0:
            raise Exception('Root block encountered unexpectedly while ordering graph')
        order = exclude_from(Graph.order_from(early_node, late_node.parent), carry)
        if late_node.uncle is not None:
            order += exclude_from(Graph.order_from(early_node, late_node.uncle), carry + order)
        return order + [late_node]

    @staticmethod
    def find_pivot(b1, b2):
        # conjecture: rewinding back to the lowest common parent in the primary chain (chain made of pri parents) is sufficient
        for past_block in b1.primary_chain:
            if past_block in b2.primary_chain:
                return past_block
        return None  # should probably not return None but do something else useful


graph = Graph()

# P2P

port = 2281
seeds = [('xk.io', port)]
p2p = Spore(seeds, ('0.0.0.0', port))


# Associated Structures

class Signature(Encodium):
    r = Integer.Definition()
    s = Integer.Definition()
    pub_x = Integer.Definition()
    pub_y = Integer.Definition()
    msg_hash = Integer.Definition()

    def check(s, changed_attributes):
        assert False not in map(is_32_bytes, [s.r, s.s, s.pub_x, s.pub_y, s.msg_hash])
        assert valid_secp256k1_signature(s.pub_x, s.pub_y, s.msg_hash, s.r, s.s)

    @classmethod
    def from_secret_exponent_and_msg(cls, secret_exponent, msg):
        msg_hash = global_hash(msg)
        r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, msg_hash)
        x, y = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
        return Signature(pub_x=x, pub_y=y, r=r, s=s, msg_hash=msg_hash)


class Transaction(Encodium):
    value = Integer.Definition()
    recipient = Integer.Definition()
    signature = Signature.Definition()

    def check(self, changed_attributes):
        assert is_4_bytes(self.value)
        assert is_32_bytes(self.recipient)


# Block structure

class QuantaBlock(Encodium):
    # Encodium

    parent_hash = Integer.Definition()
    uncle_hash = Integer.Definition(optional=True)
    target = Integer.Definition()
    tx = Transaction.Definition(optional=True)
    coinbase = Integer.Definition()
    timestamp = Integer.Definition()
    nonce = Integer.Definition()

    def __hash__(self):
        return self.hash

    def check(s, changed_attributes):
        assert False not in map(is_32_bytes, [s.parent_hash, s.target, s.coinbase])
        if s.uncle_hash != None: assert is_32_bytes(s.uncle_hash)
        assert False not in map(is_4_bytes, [s.timestamp, s.nonce])
        assert s.target < (DIFF_ONE // (256 ** 3))
        assert s.coins_generated >= 0

        s.init()

    # Setup

    def init(self):
        self._sigmadiff = None
        self._primary_chain = None
        self._mining = False
        self.parent = None
        self.uncle = None

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


def global_hash(msg: bytes):
    return int(sha256(msg).hexdigest(), 16)


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


# Messages

class BlockList(Encodium):
    blocks = List.Definition(QuantaBlock.Definition())


class BlockRequest(Encodium):
    start_hash = Integer.Definition()
    end_hash = Integer.Definition()

    def check(self, changed_attributes):
        assert False not in map(is_32_bytes, [self.start_hash, self.end_hash])


# Message Handlers

@p2p.on_message(PUSHBLOCKS, BlockList)
def respond_to_push(peer, block_list):
    graph.add_blocks(block_list.blocks)


@p2p.on_message(PULLBLOCKS, BlockRequest)
def respond_to_pull(peer, block_request):
    global block_index
    try:
        peer.send(PUSHBLOCKS, BlockList(
            blocks=Graph.order_from(block_index[block_request.start_hash], block_index[block_request.end_hash])))
    except:
        peer.disconnect()


graph.set_root(QuantaBlock(parent_hash=0, target=(DIFF_ONE // (256 ** 3) - 1), coinbase=0, timestamp=0,
                   nonce=1901667))  # this is the genesis block

