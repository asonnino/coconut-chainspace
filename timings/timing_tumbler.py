"""Performance measurements for authenticated bank contract."""
import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import tumbler
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
## coconut parameters
t, n, q = 4, 5, 3 # threshold parameters
bp_params = setup(q) # bp system's parameters
(sk, vk) = ttp_keygen(bp_params, t, n) # signers keys
aggr_vk = aggregate_vk(bp_params, vk, threshold=True)



####################################################################
# create all transactions
####################################################################
# init
init_tx = tumbler.init()
token = init_tx['transaction']['outputs'][0]

# initialise petition
create_tx = tumbler.create_tumbler(
    (token,),
    None,
    None,
    aggr_vk
)
old_list = create_tx['transaction']['outputs'][1]

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
redeem_tx = tumbler.redeem(
    (old_list,),
    None,
    (dumps(addr),),
    sigma,
    aggr_vk,
    ID
)



####################################################################
# main
####################################################################
RUNS = 2
def main():
    tumbler.contract._populate_empty_checkers()
    print "operation\t\tmean (ms)\t\tsd (ms)\t\truns"

    # == init ===============
    init_tx = tumbler.init()

    # == create_tumbler ===============
    # gen
    run(RUNS, '[g] create_tumbler', tumbler.create_tumbler, 
        (token,),
        None,
        None,
        aggr_vk
    )
    
    # check
    run_checker(RUNS, '[c] create_tumbler', 
        tumbler.contract.checkers['create_tumbler'],
        transaction_to_solution(create_tx)
    )

    # == redeem ===============
    # gen
    run(RUNS, '[g] redeem', tumbler.redeem, 
        (old_list,),
        None,
        (dumps(addr),),
        sigma,
        aggr_vk,
        ID
    )
    
    # check
    run_checker(RUNS, '[c] redeem', 
        tumbler.contract.checkers['redeem'],
        transaction_to_solution(redeem_tx)
    )


####################################################################
if __name__ == '__main__':
    main()

