""" 
	Coin tumbler.
"""


####################################################################
# imports
####################################################################
# general
from hashlib import sha256
from json import dumps, loads
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.utils import *
from chainspacecontract.examples.tumbler_proofs import *
from coconut.utils import *
from coconut.scheme import *
# chainspace
from chainspacecontract import ChainspaceContract

## contract name
contract = ChainspaceContract('tumbler')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'TToken'}),),
    }

# ------------------------------------------------------------------
# create tumbler
# ------------------------------------------------------------------
@contract.method('create_tumbler')
def create_tumbler(inputs, reference_inputs, parameters, aggr_vk):
    # spent lists
    spent_list = {
        'type' : 'TList',
        'list' : [],
        'vk'  : pack(aggr_vk)
    }

    # return
    return {
        'outputs': (inputs[0], dumps(spent_list)),
    }


# ------------------------------------------------------------------
# redeem
# ------------------------------------------------------------------
@contract.method('redeem')
def redeem(inputs, reference_inputs, parameters, sig, vk, ID):
    old_list = loads(inputs[0])
    new_list = loads(inputs[0])
    addr = loads(parameters[0])

    # proof
    bp_params = setup(2)
    (kappa, nu, sigma, zeta, pi_tumbler) = make_proof_tumbler(bp_params, vk, sig, ID, addr)
    #assert verify_proof_tumbler(bp_params, vk, sig, kappa, nu, zeta, pi_tumbler, addr)

    # update spent list
    new_list['list'].append(pack(zeta))

    # return
    return {
        'outputs': (dumps(new_list),),
        'extra_parameters' : (pack(sigma), pack(kappa), pack(nu), pack(zeta), pack(pi_tumbler))
    }



####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check tumbler's creation
# ------------------------------------------------------------------
@contract.checker('create_tumbler')
def create_tumbler_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve ID list
        spent_list = loads(outputs[1])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'TToken' or loads(outputs[0])['type'] != 'TToken': return False
        if spent_list['type'] != 'TList': return False

        # check fields
        spent_list['vk']
        if spent_list['list']: return False # check list is empty

        # otherwise
        return True

    except (KeyError, Exception):
        return False


# ------------------------------------------------------------------
# check add score
# ------------------------------------------------------------------
@contract.checker('redeem')
def redeem_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve ID list
        old_list = loads(inputs[0])
        new_list = loads(outputs[0])
        # retrieve parameters
        addr = loads(parameters[0])
        sig = unpack(parameters[1])
        kappa = unpack(parameters[2])
        nu = unpack(parameters[3])
        zeta = unpack(parameters[4])
        pi_tumbler = unpack(parameters[5])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 

        # check types
        if new_list['type'] != 'TList': return False      

        # check fields
        if new_list['vk'] != new_list['vk']: return False

        # check spent list
        zeta_packed = parameters[4]
        if (zeta_packed in old_list['list']) or (new_list['list'] != old_list['list'] + [zeta_packed]):
            return False

        # verify coin
        bp_params = setup(2)
        vk = unpack(new_list['vk'])
        if not verify_proof_tumbler(bp_params, vk, sig, kappa, nu, zeta, pi_tumbler, addr): return False
  
        # otherwise
        return True

    except (KeyError, Exception): 
        return False


####################################################################
# main
####################################################################
if __name__ == '__main__':
    contract.run()



####################################################################
