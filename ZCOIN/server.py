import time
import hashlib
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa

from miner_config import MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        """Returns a new Block object. Each block is "chained" to its previous
        by calling its unique hash.

        Args:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be sent.
            previous_hash(str): String representing previous block unique hash.

        Attrib:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be sent.
            previous_hash(str): String representing previous block unique hash.
            hash(str): Current block unique hash.

        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """Creates the unique hash for the block. It uses sha256."""
        sha = hashlib.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()


def create_genesis_block():
    """To create each block, it needs the hash of the previous one. First
    block has no previous, so it must be created manually (with index zero
     and arbitrary previous hash)"""
    return Block(0, time.time(), {
        "proof-of-work": 9,
        "transactions": None},
        "0")


# Node's blockchain copy
BLOCKCHAIN = [create_genesis_block()]

""" Stores the transactions that this node has in a list.
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []


def validate_blockchain(block):
    """Validate the submitted chain. If hashes are not correct, return false
    block(str): json
    """
    return True

@node.route('/blocks', methods=['GET'])
def get_blocks():
    # Load current blockchain. Only you should update your blockchain
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = pipe_input.recv()
    chain_to_send = BLOCKCHAIN
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "data": str(block.data),
            "hash": block.hash
        }
        chain_to_send_json.append(block)

    # Send our chain to whomever requested it
    chain_to_send = json.dumps(chain_to_send_json, sort_keys=True)
    return chain_to_send


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
    """Each transaction sent to this node gets validated and submitted.
    Then it waits to be added to the blockchain. Transactions only move
    coins, they don't create it.
    """
    if request.method == 'POST':
        # On each new POST request, we extract the transaction data
        new_txion = request.get_json()
        # Then we add the transaction to our list
        if validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
            NODE_PENDING_TRANSACTIONS.append(new_txion)
            # Because the transaction was successfully
            # submitted, we log it to our console
            print("New transaction")
            print("FROM: {0}".format(new_txion['from']))
            print("TO: {0}".format(new_txion['to']))
            print("AMOUNT: {0}\n".format(new_txion['amount']))
            # Then we let the client know it worked out
            return "Transaction submission successful\n"
        else:
            return "Transaction submission failed. Wrong signature\n"
    # Send pending transactions to the mining process
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS, sort_keys=True)
        # Empty transaction list
        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct. This is used to prove
    it's you (and not someone else) trying to do a transaction with your
    address. Called when a user tries to submit a new transaction.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    # Try changing into an if/else statement as except is too broad.
    try:
        return vk.verify(signature, message.encode())
    except:
        return False


def welcome_msg():
    print("""\n\n=========================================\n
        ZCOIN - BLOCKCHAIN SERVER\n
=========================================\n
https://github.com/KTSOEV/ZCOIN\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    pipe_output, pipe_input = Pipe()

    # Start server to receive transactions
    transactions_process = Process(target=node.run(), args=pipe_input)
    transactions_process.start()
