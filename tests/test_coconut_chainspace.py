""" test Coconut smart contract library """

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
(sk, vk) = ttp_keygen(params, t, n) # signers keys
aggr_vk = agg_key(params, vk, threshold=True)



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

            # issue a credential
            transaction = coconut_chainspace.issue(
                (old_request,),
                None,
                (0,),
                sk[0]
            )
            old_request = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/issue', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            # issue the other credential
            for i in range(1,n):
                transaction = coconut_chainspace.issue(
                    (old_request,),
                    None,
                    (i,),
                    sk[i]
                )
                old_request = transaction['transaction']['outputs'][0]

            # some crypto - to show that this actually works
            # ------------------------------------
            packed_sigs_tilde = loads(old_request)['sigs']
            sigs_tilde = [unpack(x) for x in packed_sigs_tilde]
            sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
            aggr_sigma = agg_cred(params, sigs)
            Theta = prove_cred(params, aggr_vk, aggr_sigma, private_m)
            print("\n\n=================== VERIFICATION ===================\n")
            print(verify_cred(params, aggr_vk, Theta, public_m=public_m))
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

            # issue a credentials
            transaction = coconut_chainspace.issue(
                (old_request,),
                None,
                (0,),
                sk[0]
            )
            old_request = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/issue', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            # issue the other credentials
            for i in range(1,n):
                transaction = coconut_chainspace.issue(
                    (old_request,),
                    None,
                    (i,),
                    sk[i]
                )
                old_request = transaction['transaction']['outputs'][0]

            # some crypto - to show that this actually works
            # ------------------------------------
            packed_sigs_tilde = loads(old_request)['sigs']
            sigs_tilde = [unpack(x) for x in packed_sigs_tilde]
            sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
            aggr_sigma = agg_cred(params, sigs)
            # ------------------------------------

            # verify signature
            transaction = coconut_chainspace.verify(
                None,
                (instance,),
                (dumps(public_m),),
                aggr_sigma,
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
