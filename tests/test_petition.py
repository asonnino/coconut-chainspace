""" test authenticated bank transfer """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from json import dumps, loads
import time
import unittest
import requests
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.petition import contract as petition_contract
from chainspacecontract.examples import petition
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.utils import *
from coconut.utils import *
from coconut.scheme import *



####################################################################
## petition parameters
UUID = Bn(1234) # petition unique id (needed for crypto)
options = ['YES', 'NO'] # options 
pet_params = pet_setup()
(G, g, hs, o) = pet_params
priv_owner = o.random() # should be threshold
pub_owner = priv_owner*g # should be threshold

## coconut parameters
t, n = 4, 5 # threshold and total numbero of authorities
bp_params = setup() # bp system's parameters
(sk, vk) = ttp_keygen(bp_params, t, n) # signers keys
aggr_vk = aggregate_vk(bp_params, vk, threshold=True)



class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        with petition_contract.test_service():
            ## create transaction
            transaction = petition.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + petition_contract.contract_name 
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])



    # --------------------------------------------------------------
    # test create petition
    # --------------------------------------------------------------
    def test_create_petition(self):
        with petition_contract.test_service():
            ## create transaction
            # init
            init_transaction = petition.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise petition
            transaction = petition.create_petition(
                (token,),
                None,
                None,
                UUID,
                options,
                priv_owner,
                pub_owner,
                aggr_vk
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + petition_contract.contract_name 
                + '/create_petition', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

 
    # --------------------------------------------------------------
    # test sign
    # --------------------------------------------------------------
    def test_sign(self):
        with petition_contract.test_service():
            # create transaction
            # init
            init_transaction = petition.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise petition
            create_petition_transaction = petition.create_petition(
                (token,),
                None,
                None,
                UUID,
                options,
                priv_owner,
                pub_owner,
                aggr_vk
            )
            old_petition = create_petition_transaction['transaction']['outputs'][1]
            old_list = create_petition_transaction['transaction']['outputs'][2]

            # some crypto to get the credentials
            # ------------------------------------
            (d, gamma) = elgamal_keygen(bp_params)
            private_m = [d]
            (cm, c, pi_s) = prepare_blind_sign(bp_params, gamma, private_m)
            sigs_tilde = [blind_sign(bp_params, ski, cm, c, gamma, pi_s) for ski in sk]
            sigs = [unblind(bp_params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
            sigma = aggregate_sigma(bp_params, sigs)
            sigma = randomize(bp_params, sigma)
            # ------------------------------------

            # add signature to th petition
            transaction = petition.sign(
                (old_petition, old_list),
                None,
                None,
                d,
                sigma,
                aggr_vk,
                1
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + petition_contract.contract_name 
                + '/sign', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])


    # --------------------------------------------------------------
    # test tally
    # --------------------------------------------------------------
    def test_tally(self):
        with petition_contract.test_service():
            # create transaction
            # init
            init_transaction = petition.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise petition
            create_petition_transaction = petition.create_petition(
                (token,),
                None,
                None,
                UUID,
                options,
                priv_owner,
                pub_owner,
                aggr_vk
            )
            old_petition = create_petition_transaction['transaction']['outputs'][1]
            old_list = create_petition_transaction['transaction']['outputs'][2]

            # add signature to the petition
            for i in range(3):
                # some crypto to get the credentials
                # ------------------------------------
                (d, gamma) = elgamal_keygen(bp_params)
                private_m = [d]
                (cm, c, pi_s) = prepare_blind_sign(bp_params, gamma, private_m)
                sigs_tilde = [blind_sign(bp_params, ski, cm, c, gamma, pi_s) for ski in sk]
                sigs = [unblind(bp_params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
                sigma = aggregate_sigma(bp_params, sigs)
                sigma = randomize(bp_params, sigma)
                # ------------------------------------

                sign_transaction = petition.sign(
                    (old_petition, old_list),
                    None,
                    None,
                    d,
                    sigma,
                    aggr_vk,
                    1
                )
                old_petition = sign_transaction['transaction']['outputs'][0]
                old_list = sign_transaction['transaction']['outputs'][1]

            # tally
            transaction = petition.tally(
                (old_petition,),
                None,
                None,
                priv_owner,
                pub_owner
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + petition_contract.contract_name 
                + '/tally', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            print("\n\n=================== VERIFICATION ===================\n")
            print('OUTCOME: ', loads(transaction['transaction']['outputs'][0])['outcome'])
            print("\n====================================================\n\n")

   
####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
