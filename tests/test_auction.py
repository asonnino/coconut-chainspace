""" test auction """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
import time
import unittest
import requests
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.auction import contract as auction_contract
from chainspacecontract.examples import auction
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.utils import *
from coconut.utils import *
from coconut.scheme import *


####################################################################
# authenticated bank transfer
####################################################################
## auction parameters
t, n, q = 4, 5, 3 # threshold parameters
bp_params = setup(q) # bp system's parameters
(G, o, g1, hs, g2, e) = bp_params
(sk, vk) = ttp_keygen(bp_params, t, n) # authorities keys
aggr_vk = agg_key(bp_params, vk, threshold=True)
t_commit, t_reveal = 100, 1000 # auction timeline
uid = '1234' # auction id
v0, ov0 = 350, o.random() # minimum price
addr = Bn(50) # bidder address for withdrawal
file_hash = Bn(500) # winner file hash

## simulate deposit
bidders = []
for i in range(1,5):
    seq, v = o.random(), i
    (d, gamma) = elgamal_keygen(bp_params)
    private_m = [seq, v]
    Lambda = prepare_blind_sign(bp_params, gamma, private_m)
    sigs_tilde = [blind_sign(bp_params, ski, gamma, Lambda) for ski in sk]
    sigs = [unblind(bp_params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
    sigma = agg_cred(bp_params, sigs)
    bidders.append((seq, v, sigma))


class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        with auction_contract.test_service():
            ## create transaction
            transaction = auction.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test create
    # --------------------------------------------------------------
    def test_create(self):
       with auction_contract.test_service():
            ## create transaction
            # init
            init_transaction = auction.init()
            token = init_transaction['transaction']['outputs'][0]

            # create auction
            transaction = auction.create(
                (token,),
                None,
                None,
                aggr_vk,
                t_commit,
                t_reveal,
                uid,
                v0,
                ov0
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/create', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test commit
    # --------------------------------------------------------------
    def test_commit(self):
        with auction_contract.test_service():
            ## create transaction
            # init
            init_transaction = auction.init()
            token = init_transaction['transaction']['outputs'][0]

            # create auction
            auction_transaction = auction.create(
                (token,),
                None,
                None,
                aggr_vk,
                t_commit,
                t_reveal,
                uid,
                v0,
                ov0
            )
            auction_object = auction_transaction['transaction']['outputs'][1]

            ## commit
            transaction = auction.commit(
                (auction_object, ),
                None,
                None,
                bidders[0][0], # seq
                bidders[0][1], # v
                bidders[0][2] # sigma
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/commit', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test reveal
    # --------------------------------------------------------------
    def test_reveal(self):
        with auction_contract.test_service():
            ## create transaction
            # init
            init_transaction = auction.init()
            token = init_transaction['transaction']['outputs'][0]

            # create auction
            auction_transaction = auction.create(
                (token,),
                None,
                None,
                aggr_vk,
                t_commit,
                t_reveal,
                uid,
                v0,
                ov0
            )
            auction_object = auction_transaction['transaction']['outputs'][1]

            ## commit
            for i in range(len(bidders)):
                commit_transaction = auction.commit(
                    (auction_object, ),
                    None,
                    None,
                    bidders[i][0], # seq
                    bidders[i][1], # v
                    bidders[i][2] # sigma
                )
                auction_object = commit_transaction['transaction']['outputs'][0]

            ## reveal
            transaction = auction.reveal(
                (auction_object, ),
                None,
                (dumps(bidders[1][1]),), # v
                bidders[1][0], # seq
                bidders[1][2] # sigma
            )
            
            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/reveal', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])
   
    # --------------------------------------------------------------
    # test withdraw
    # --------------------------------------------------------------
    def test_withdraw(self):
        with auction_contract.test_service():
            ## create transaction
            # init
            init_transaction = auction.init()
            token = init_transaction['transaction']['outputs'][0]

            # create auction
            auction_transaction = auction.create(
                (token,),
                None,
                None,
                aggr_vk,
                t_commit,
                t_reveal,
                uid,
                v0,
                ov0
            )
            auction_object = auction_transaction['transaction']['outputs'][1]

            ## commit
            for i in range(len(bidders)):
                commit_transaction = auction.commit(
                    (auction_object, ),
                    None,
                    None,
                    bidders[i][0], # seq
                    bidders[i][1], # v
                    bidders[i][2] # sigma
                )
                auction_object = commit_transaction['transaction']['outputs'][0]

            ## reveal
            for i in range(len(bidders)):
                reveal_transaction = auction.reveal(
                    (auction_object, ),
                    None,
                    (dumps(bidders[i][1]),), # v
                    bidders[i][0], # seq
                    bidders[i][2] # sigma
                )
                auction_object = reveal_transaction['transaction']['outputs'][0]
                    
            ## withdraw
            transaction = auction.withdraw(
                (auction_object, ),
                None,
                (dumps(bidders[1][1]), pack(addr)),
                bidders[1][0], # seq
                bidders[1][2] # sigma
            )
            
            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/withdraw', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])
    
    # --------------------------------------------------------------
    # test submitWork
    # --------------------------------------------------------------
    def test_submitWork(self):
        with auction_contract.test_service():
            ## create transaction
            # init
            init_transaction = auction.init()
            token = init_transaction['transaction']['outputs'][0]

            # create auction
            auction_transaction = auction.create(
                (token,),
                None,
                None,
                aggr_vk,
                t_commit,
                t_reveal,
                uid,
                v0,
                ov0
            )
            auction_object = auction_transaction['transaction']['outputs'][1]

            ## commit
            for i in range(len(bidders)):
                commit_transaction = auction.commit(
                    (auction_object, ),
                    None,
                    None,
                    bidders[i][0], # seq
                    bidders[i][1], # v
                    bidders[i][2] # sigma
                )
                auction_object = commit_transaction['transaction']['outputs'][0]

            ## reveal
            for i in range(len(bidders)):
                reveal_transaction = auction.reveal(
                    (auction_object, ),
                    None,
                    (dumps(bidders[i][1]),), # v
                    bidders[i][0], # seq
                    bidders[i][2] # sigma
                )
                auction_object = reveal_transaction['transaction']['outputs'][0]

            ## withdraw
            withdraw_transaction = auction.withdraw(
                (auction_object, ),
                None,
                (dumps(bidders[1][1]), pack(addr)),
                bidders[1][0], # seq
                bidders[1][2] # sigma
            )
            auction_object = reveal_transaction['transaction']['outputs'][0]
            
            ## submitWork
            transaction = auction.submitWork(
                (auction_object, ),
                None,
                (dumps(bidders[3][1]), pack(file_hash)),
                bidders[3][0], # seq
                bidders[3][2] # sigma
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + auction_contract.contract_name
                + '/submitWork', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            
####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
