"""Performance measurements for auction contract."""
import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import auction
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



####################################################################
# create all transactions
####################################################################
# init
init_tx = auction.init()
token = init_tx['transaction']['outputs'][0]

create_tx = auction.create(
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
auction_object_1 = create_tx['transaction']['outputs'][1]

commit_tx = auction.commit(
    (auction_object_1, ),
    None,
    None,
    bidders[0][0], # seq
    bidders[0][1], # v
    bidders[0][2] # sigma
)
auction_object_2 = commit_tx['transaction']['outputs'][0]

reveal_tx = auction.reveal(
    (auction_object_2, ),
    None,
    (dumps(bidders[0][1]),), # v
    bidders[0][0], # seq
    bidders[0][2] # sigma
)
auction_object_3 = reveal_tx['transaction']['outputs'][0]

withdraw_tx = auction.withdraw(
    (auction_object_3, ),
    None,
    (dumps(bidders[0][1]), pack(addr)),
    bidders[0][0], # seq
    bidders[0][2] # sigma
)
auction_object_4 = withdraw_tx['transaction']['outputs'][0]


submitWork_tx = auction.submitWork(
    (auction_object_3, ),
    None,
    (dumps(bidders[0][1]), pack(file_hash)),
    bidders[0][0], # seq
    bidders[0][2] # sigma
)
auction_object_5 = submitWork_tx['transaction']['outputs'][0]



####################################################################
# main
####################################################################
RUNS = 2
def main():
    auction.contract._populate_empty_checkers()
    print "operation\t\tmean (ms)\t\tsd (ms)\t\truns"

    # == create ===============
    # gen
    run(RUNS, '[g] create', auction.create,
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
    # check
    run_checker(RUNS, '[c] create',
        auction.contract.checkers['create'],
        transaction_to_solution(create_tx)
    )
    
    # == commit ===============
    # gen
    run(RUNS, '[g] commit', auction.commit,
        (auction_object_1, ),
        None,
        None,
        bidders[0][0], # seq
        bidders[0][1], # v
        bidders[0][2] # sigma
    )
    # check
    run_checker(RUNS, '[c] commit',
        auction.contract.checkers['commit'],
        transaction_to_solution(commit_tx)
    )

    # == reveal ===============
    # gen
    run(RUNS, '[g] reveal', auction.reveal,
        (auction_object_2, ),
        None,
        (dumps(bidders[0][1]),), # v
        bidders[0][0], # seq
        bidders[0][2] # sigma
    )
    # check
    run_checker(RUNS, '[c] reveal',
        auction.contract.checkers['reveal'],
        transaction_to_solution(reveal_tx)
    )

    # == withdraw ===============
    # gen
    run(RUNS, '[g] reveal', auction.withdraw,
        (auction_object_3, ),
        None,
        (dumps(bidders[0][1]), pack(addr)),
        bidders[0][0], # seq
        bidders[0][2] # sigma
    )
    # check
    run_checker(RUNS, '[c] withdraw',
        auction.contract.checkers['withdraw'],
        transaction_to_solution(withdraw_tx)
    )

    # == submitWork ===============
    # gen
    run(RUNS, '[g] submitWork', auction.withdraw,
        (auction_object_3, ),
        None,
        (dumps(bidders[0][1]), pack(file_hash)),
        bidders[0][0], # seq
        bidders[0][2] # sigma
    )
    # check
    run_checker(RUNS, '[c] submitWork',
        auction.contract.checkers['submitWork'],
        transaction_to_solution(submitWork_tx)
    )


####################################################################
if __name__ == '__main__':
    main()

