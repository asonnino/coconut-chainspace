""" test authenticated bank transfer """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from hashlib import sha256
from binascii import hexlify, unhexlify
from json import dumps, loads
import time
import unittest
import requests
# cypto
from petlib.bn import Bn
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.coconut_chainspace import contract as coconut_contract
from chainspacecontract.examples import coconut_chainspace
# coconut
from chainspacecontract.examples.utils import *
from coconut.utils import *
from coconut.scheme import *



####################################################################
q = 5 # max number of messages
t, n = 2, 3 # threshold and total numbero of authorities
callback = 'hello.init' # id of the callback contract
params = setup(q) # system's parameters
public_m = [1, 2] # messages for plaintext signature
private_m = [3, 4, 5] # messages for blind signature
(d, gamma) = elgamal_keygen(params) # user's key pair 
(sk, vk) = ttp_keygen(params, t, n, q) # signers keys
aggr_vk = aggregate_vk(params, vk, threshold=True)



class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        with coconut_contract.test_service():
            ## create transaction
            transaction = coconut_chainspace.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test create instance
    # --------------------------------------------------------------
    def test_create(self):
        with coconut_contract.test_service():
            ## create transaction
            # init
            init_transaction = coconut_chainspace.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            transaction = coconut_chainspace.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                aggr_vk,
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/create', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test request
    # --------------------------------------------------------------
    def test_request(self):
        with coconut_contract.test_service():
            ## create transactions
            # init
            init_transaction = coconut_chainspace.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut_chainspace.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                aggr_vk,
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            transaction = coconut_chainspace.request(
                (instance,),
                None,
                None,
                public_m, 
                private_m, 
                gamma
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/request', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test issue
    # --------------------------------------------------------------
    def test_issue(self):
        with coconut_contract.test_service():
            ## create transactions
            # init
            init_transaction = coconut_chainspace.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut_chainspace.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                aggr_vk,
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            request_transaction = coconut_chainspace.request(
                (instance,),
                None,
                None,
                public_m, 
                private_m, 
                gamma
            )
            old_request = request_transaction['transaction']['outputs'][1]

            # issue a signatures
            transaction = coconut_chainspace.issue(
                (old_request,),
                None,
                None,
                sk[0],
                0
            )
            old_request = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/issue', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            # issue the other t-1 signatures
            for i in range(1,t):
                transaction = coconut_chainspace.issue(
                    (old_request,),
                    None,
                    None,
                    sk[i],
                    i
                )
                old_request = transaction['transaction']['outputs'][0]

            # some crypto - to show that this actually works
            # ------------------------------------
            packet = loads(old_request)['sigs']
            (indexes, packed_sigma_tilde) = zip(*packet)
            sigma_tilde = [unpack(x) for x in packed_sigma_tilde]
            (h, enc_s) = zip(*sigma_tilde)
            dec_sigs = [(h[0], elgamal_dec(params, d, enc)) for enc in enc_s]
            aggr_sigma = aggregate_sigma(params, dec_sigs)
            aggr_sigma = randomize(params, aggr_sigma)
            (kappa, nu, pi_v) = show_blind_sign(params, aggr_vk, aggr_sigma, private_m)
            print("\n\n=================== VERIFICATION ===================\n")
            print(blind_verify(params, aggr_vk, aggr_sigma, kappa, nu, pi_v, public_m=public_m))
            print("\n====================================================\n\n")
            # ------------------------------------

    # --------------------------------------------------------------
    # test verify
    # --------------------------------------------------------------
    def test_verify(self):
        with coconut_contract.test_service():
            ## create transactions
            # init
            init_transaction = coconut_chainspace.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut_chainspace.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                aggr_vk,
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            request_transaction = coconut_chainspace.request(
                (instance,),
                None,
                None,
                public_m, 
                private_m, 
                gamma
            )
            old_request = request_transaction['transaction']['outputs'][1]

            # issue a signatures
            transaction = coconut_chainspace.issue(
                (old_request,),
                None,
                None,
                sk[0],
                0
            )
            old_request = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/issue', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            # issue the other t-1 signatures
            for i in range(1,t):
                transaction = coconut_chainspace.issue(
                    (old_request,),
                    None,
                    None,
                    sk[i],
                    i
                )
                old_request = transaction['transaction']['outputs'][0]

            # some crypto - to show that this actually works
            # ------------------------------------
            packet = loads(old_request)['sigs']
            (indexes, packed_sigma_tilde) = zip(*packet)
            sigma_tilde = [unpack(x) for x in packed_sigma_tilde]
            (h, enc_s) = zip(*sigma_tilde)
            dec_sigs = [(h[0], elgamal_dec(params, d, enc)) for enc in enc_s]
            aggr_sigma = aggregate_sigma(params, dec_sigs)
            aggr_sigma = randomize(params, aggr_sigma)
            # ------------------------------------

            # verify signature
            transaction = coconut_chainspace.verify(
                None,
                (instance,),
                (pack(aggr_sigma),),
                public_m,
                private_m
            )

            ## submit t ransaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/verify', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            print("\n\n=================== VERIFICATION ===================\n")
            print(transaction['transaction']['returns'][0])
            print("\n====================================================\n\n")
    

####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
