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

head = None  # for a block to be added (and become head), parent must be head and uncle must be in orphans
root = None  # this is the genesis block
orphans = set()  # for a block to be added (that's not head), parent and uncle must be in orphans
state = State()
block_index = {}


# P2P

port = 2281
seeds = [('xk.io', port)]
p2p = Spore(seeds, ('0.0.0.0', port))


# Helpers

def is_32_bytes(i):
    return 0 < i < 256 ** 32


def is_4_bytes(i):
    return 0 < i < 256 ** 4


def global_hash(msg: bytes):
    return int(sha256(msg).hexdigest(), 16)


def hash_block(block: QuantaBlock):
    return global_hash(bytes(block.to_json()))


def target_to_diff(target):
    return DIFF_ONE // target


# Crypto Helpers

def valid_secp256k1_signature(x, y, msg, r, s):
    return ecdsa.verify(ecdsa.generator_secp256k1, (x, y), global_hash(msg), (r, s))


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

    def check(s, changed_attributes):
        assert False not in map(is_32_bytes, [s.parent_hash, s.target, s.tx_hash, s.coinbase])
        if s.uncle_hash != None: assert is_32_bytes(s.uncle_hash)
        assert False not in map(is_4_bytes, [s.timestamp, s.nonce])
        assert s.target < (DIFF_ONE // (256 ** 4))
        assert coins_generated(s) >= 0
        assert s.hash < s.target

    # Setup

    def init(self):
        self._sigmadiff = None
        self._primary_chain = None

    # Graph

    def set_parent(self, parent):
        assert parent.hash == self.parent_hash
        self.parent, = parent

    def set_uncle(self, uncle):
        if uncle == None:
            return
        assert uncle.hash == self.uncle_hash
        self.uncle = uncle

    @property
    def primary_chain(self):
        if self._primary_chain == None:
            self._primary_chain = [self] + self.parent.primary_chain
        return self._primary_chain

    # Properties

    @property
    def hash(self):
        return hash_block(self)

    @property
    def sigmadiff(self):
        if self._sigmadiff == None:
            self._sigmadiff = sum(map(target_to_diff, [i.target for i in order_from(root, self)]))
        return self._sigmadiff


# Graph Functions

def order_from(early_node, late_node, carry=[]):
    if early_node == late_node: return [late_node]
    if late_node.parent_hash == 0:
        raise Exception('Root block encountered unexpectedly while ordering graph')
    order = exclude_from(order_from(early_node, late_node.parent), carry)
    if late_node.uncle is not None:
        order += exclude_from(order_from(early_node, late_node.uncle), carry + order)
    return order + [late_node]


def exclude_from(a, b):
    return [i for i in a if i not in b]


def process_blocks(blocks):
    global state
    backup_state = deepcopy(state)
    try:
        for block in blocks:
            _process_block(block)
    except:
        state = backup_state


def _process_block(block):
    if block.parent_hash not in block_index or (block.uncle is not None and block.uncle not in block_index):
        pass
    block.set_parent(block_index[block.parent_hash])
    if block.uncle_hash is not None: block.set_uncle(block_index[block.uncle_hash])
    if better_than_head(block):
        reorganize(block)
    else:
        orphans.add(block)


def better_than_head(block):
    return block.sigmadiff > head.sigmadiff


def reorganize(block):
    pivot = find_pivot(head, block)
    mass_unapply(order_from(pivot, head))
    mass_apply(order_from(pivot, block))


def find_pivot(b1, b2):
    # conjecture: rewinding back to the lowest common parent in the primary chain (chain made of pri parents) is sufficient
    for past_block in b1.primary_chain:
        if past_block in b2.primary_chain:
            return past_block
    return None  # should probably not return None but do something else useful


def mass_unapply(path):
    for block in path[::-1]:
        unapply_to_state(block)
        orphans.add(block)


def mass_apply(path):
    for block in path:
        assert valid_for_state(block)
        apply_to_state(block)
        orphans.remove(block)


# State Functions

def valid_for_state(block):
    return state.get(block.tx.signature.pub_x) >= block.tx.value


def apply_to_state(block):
    modify_state(block, 1)


def unapply_to_state(block):
    modify_state(block, -1)


def modify_state(block, direction):
    assert direction in [-1, 1]
    if block.tx is not None:
        state.move_coins(block.tx.recipient, direction * block.tx.value)
        state.move_coins(block.tx.signature.pub_x, -1 * direction * block.tx.value)
    state.move_coins(block.coinbase, direction * coins_generated(block))


# Monetary Functions

def coins_generated(block):
    return DIFF_ONE // block.target - storage_fee(block)


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
    global state, head
    old_head = head
    backup_state = deepcopy(state)
    try:
        process_blocks(block_list.blocks)
    except:
        peer.disconnect()
        state = backup_state
        head = old_head


@p2p.on_message(PULLBLOCKS, BlockRequest)
def respond_to_pull(peer, block_request):
    global block_index
    try:
        peer.send(PUSHBLOCKS, BlockList(blocks=order_from(block_index[block_request.start_hash], block_index[block_request.end_hash])))
    except:
        peer.disconnect()