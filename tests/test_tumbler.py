""" test authenticated bank transfer """

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
from chainspacecontract.examples.tumbler import contract as tumbler_contract
from chainspacecontract.examples import tumbler
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
## coconut parameters
t, n, q = 4, 5, 3 # threshold parameters
bp_params = setup(q) # bp system's parameters
(sk, vk) = ttp_keygen(bp_params, t, n) # signers keys
aggr_vk = aggregate_vk(bp_params, vk, threshold=True)



class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        with tumbler_contract.test_service():
            ## create transaction
            transaction = tumbler.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + tumbler_contract.contract_name 
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])


    # --------------------------------------------------------------
    # test create tumbler
    # --------------------------------------------------------------
    def test_create_tumbler(self):
       with tumbler_contract.test_service():
            ## create transaction
            # init
            init_transaction = tumbler.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise petition
            transaction = tumbler.create_tumbler(
                (token,),
                None,
                None,
                aggr_vk,
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + tumbler_contract.contract_name
                + '/create_tumbler', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])


    # --------------------------------------------------------------
    # test redeem
    # --------------------------------------------------------------
    def test_redeem(self):
        with tumbler_contract.test_service():
            ## create transaction
            # init
            init_transaction = tumbler.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise petition
            create_transaction = tumbler.create_tumbler(
                (token,),
                None,
                None,
                aggr_vk
            )
            old_list = create_transaction['transaction']['outputs'][1]

            # some crypto
            # ------------------------------------
            ID = 10 # sequence number embedded in the credentials  
            addr = 100 # merchant address
            (d, gamma) = elgamal_keygen(bp_params)
            private_m = [ID, addr]
            (cm, c, pi_s) = prepare_blind_sign(bp_params, gamma, private_m)
            sigs_tilde = [blind_sign(bp_params, ski, cm, c, gamma, pi_s) for ski in sk]
            sigs = [unblind(bp_params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
            sigma = aggregate_sigma(bp_params, sigs)
            sigma = randomize(bp_params, sigma)
            # ------------------------------------

            # add signature to th petition
            transaction = tumbler.redeem(
                (old_list,),
                None,
                (dumps(addr),),
                sigma,
                aggr_vk,
                ID
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + tumbler_contract.contract_name 
                + '/redeem', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

   
####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
