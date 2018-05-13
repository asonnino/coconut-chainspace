import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import petition
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.utils import *
from coconut.utils import *
from coconut.scheme import *

## timing functions
from chainspacecontract.timings.run import *


####################################################################
# parameters
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


####################################################################
# create all transactions
####################################################################
# init
init_tx = petition.init()
token = init_tx['transaction']['outputs'][0]

# create_petition
create_petition_tx = petition.create_petition(
    (token,),
    None,
    None,
    UUID,
    options,
    priv_owner,
    pub_owner,
    aggr_vk
)
old_petition = create_petition_tx['transaction']['outputs'][1]
old_list = create_petition_tx['transaction']['outputs'][2]

# sign
(d, gamma) = elgamal_keygen(bp_params)
private_m = [d]
(cm, c, pi_s) = prepare_blind_sign(bp_params, gamma, private_m)
sigs_tilde = [blind_sign(bp_params, ski, cm, c, gamma, pi_s) for ski in sk]
sigs = [unblind(bp_params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
sigma = aggregate_sigma(bp_params, sigs)
sigma = randomize(bp_params, sigma)
sign_tx = petition.sign(
    (old_petition, old_list),
    None,
    None,
    d,
    sigma,
    aggr_vk,
    1
)
old_petition = sign_tx['transaction']['outputs'][0]
old_list = sign_tx['transaction']['outputs'][1]

# tally
tally_tx = petition.tally(
    (old_petition,),
    None,
    None,
    priv_owner,
    pub_owner
)



####################################################################
# main
####################################################################
RUNS = 2
def main():
    petition.contract._populate_empty_checkers()
    print("operation\t\tmean (ms)\t\tsd (ms)\t\truns")

    # == create_petition ===============
    # gen
    run(RUNS, '[g] create_petition', petition.create_petition, 
        (token,),
        None,
        None,
        UUID,
        options,
        priv_owner,
        pub_owner,
        aggr_vk
    )
    
    # check
    run_checker(RUNS, '[c] create_petition', 
        petition.contract.checkers['create_petition'],
        transaction_to_solution(create_petition_tx)
    )

    # == sign ===============
    # gen
    run(RUNS, '[g] sign', petition.sign, 
        (old_petition, old_list),
        None,
        None,
        d,
        sigma,
        aggr_vk,
        1
    )
    
    # check
    run_checker(RUNS, '[c] sign', 
        petition.contract.checkers['sign'],
        transaction_to_solution(sign_tx)
    )

    # == tally ===============
    # gen
    run(RUNS, '[g] tally', petition.tally, 
        (old_petition,),
        None,
        None,
        priv_owner,
        pub_owner
    )
    
    # check
    run_checker(RUNS, '[c] tally', 
        petition.contract.checkers['tally'],
        transaction_to_solution(tally_tx)
    )

    

####################################################################
if __name__ == '__main__':
    main()
