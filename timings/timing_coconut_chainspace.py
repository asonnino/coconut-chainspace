import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import coconut_chainspace
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
q = 5 # max number of messages
t, n = 2, 3 # threshold and total numbero of authorities
callback = 'hello.init' # id of the callback contract
params = setup(q) # system's parameters
public_m = [1, 2] # messages for plaintext signature
private_m = [3, 4, 5] # messages for blind signature
(d, gamma) = elgamal_keygen(params) # user's key pair 
(sk, vk) = ttp_keygen(params, t, n) # signers keys
aggr_vk = aggregate_vk(params, vk, threshold=True)


####################################################################
# create all transactions
####################################################################
## init
init_tx = coconut_chainspace.init()
token = init_tx['transaction']['outputs'][0]

## create
create_tx = coconut_chainspace.create(
    (token,),
    None,
    None,
    q,
    t,
    n,
    callback, 
    aggr_vk
)
instance = create_tx['transaction']['outputs'][1]

## request
request_tx = coconut_chainspace.request(
    (instance,),
    None,
    None,
    public_m, 
    private_m, 
    gamma
)
coco_request = request_tx['transaction']['outputs'][1]

## issue
issue_tx = coconut_chainspace.issue(
    (coco_request,),
    None,
    None,
    sk[0],
    0
)

## verify
(cm, c, pi_s) = prepare_blind_sign(params, gamma, private_m, public_m=public_m)
sigs_tilde = [blind_sign(params, ski, cm, c, gamma, pi_s, public_m=public_m) for ski in sk]
sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]
sigma = aggregate_sigma(params, sigs)
sigma = randomize(params, sigma)
verify_tx = coconut_chainspace.verify(
    None,
    (instance,),
    (pack(sigma),),
    public_m,
    private_m
)     



####################################################################
# main
####################################################################
RUNS = 2
def main():
    coconut_chainspace.contract._populate_empty_checkers()
    print("operation\t\tmean (ms)\t\tsd (ms)\t\truns")

    # == create ===============
    # gen
    run(RUNS, '[g] create', coconut_chainspace.create, 
        (token,),
        None,
        None,
        q,
        t,
        n,
        callback, 
        aggr_vk
    )
    
    # check
    run_checker(RUNS, '[c] create', 
        coconut_chainspace.contract.checkers['create'],
        transaction_to_solution(create_tx)
    )

    # == request ===============
    # gen
    run(RUNS, '[g] request', coconut_chainspace.request, 
        (instance,),
        None,
        None,
        public_m, 
        private_m, 
        gamma
    )
    # check
    run_checker(RUNS, '[c] request', 
        coconut_chainspace.contract.checkers['request'],
        transaction_to_solution(request_tx)
    )

    # == issue ===============
    # gen
    run(RUNS, '[g] issue', coconut_chainspace.issue, 
        (coco_request,),
        None,
        None,
        sk[0],
        0
    )
    # check
    run_checker(RUNS, '[c] issue', 
        coconut_chainspace.contract.checkers['issue'],
        transaction_to_solution(issue_tx)
    )

    # == verify ===============
    # gen
    run(RUNS, '[g] verify', coconut_chainspace.verify, 
        None,
        (instance,),
        (pack(sigma),),
        public_m,
        private_m
    )
    # check
    run_checker(RUNS, '[c] verify', 
        coconut_chainspace.contract.checkers['verify'],
        transaction_to_solution(verify_tx)
    )


####################################################################
if __name__ == '__main__':
    main()
