from audioop import add
from base64 import encode
import datetime
import hashlib
import json
from urllib import response
from flask import Flask, jsonify, request
from numpy import block
import requests
from uuid import uuid4
from urllib.parse import urlparse


class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not(check_proof):
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block['previous_hash'] != self.hash(previous_block):
                return False
            hash_operation = hashlib.sha256(
                str(current_block['proof']**2 - previous_block['proof']**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
        return True

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        return parsed_url.netloc

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            res = requests.get(f'http://{node}/chain')
            if res.status_code != 200:
                continue
            node_length = res.json()['length']
            node_chain = res.json()['chain']
            if node_length > max_length and self.is_chain_valid(node_chain):
                longest_chain = node_chain
                max_length = node_length
        if longest_chain:
            self.chain = longest_chain
            return True
        return False


# flask app
app = Flask(__name__)

blockchain = Blockchain()

node_address = str(uuid4()).replace('-', '')


@app.route('/mine', methods=['GET'])
def mine():
    previous_block = blockchain.get_previous_block()
    new_proof = blockchain.proof_of_work(previous_block['proof'])
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(node_address, node_address, 25)
    current_block = blockchain.create_block(new_proof, previous_hash)
    res = {'message': 'Block mined', 'block': current_block}
    return jsonify(res), 200


@app.route('/chain', methods=['GET'])
def chain():
    res = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(res), 200


@app.route('/is_valid', methods=['GET'])
def is_valid():
    valid = blockchain.is_chain_valid(blockchain.chain)
    res = {'valid': 'no'}
    if valid:
        res = {'valid': 'yes'}
    return jsonify(res), 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    req = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in req for key in transaction_keys):
        return jsonify({'error': 'Missing keys'}), 400
    index = blockchain.add_transaction(
        req['sender'], req['receiver'], req['amount'])
    res = {'message': f'This transaction will be added to block {index}'}
    return jsonify(res), 201


@app.route('/connect_node', methods=['POST'])
def connect_node():
    req = request.get_json()
    nodes = req.get('nodes')
    if nodes is None:
        return jsonify({'error': 'No node'}), 400
    for node in nodes:
        blockchain.add_node(node)
    res = {'message': 'Nodes connected', 'total_nodes': list(blockchain.nodes)}
    return jsonify(res), 201


@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    replaced = blockchain.replace_chain()
    res = {'replaced': 'no', 'chain': blockchain.chain}
    if replaced:
        res = {'replaced': 'yes', 'chain': blockchain.chain}
    return jsonify(res), 200


PORT = 5002

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=PORT)
