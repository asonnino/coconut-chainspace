""" Coconut smart contract library. """


####################################################################
# imports
####################################################################
# general
from json import dumps, loads
from hashlib import sha256
# cypto
from petlib.bn import Bn
# chainspace
from chainspacecontract import ChainspaceContract
# coconut
from chainspacecontract.examples.utils import *
from coconut.scheme import *
from coconut.proofs import *


## contract name
contract = ChainspaceContract('coconut_chainspace')

## dependencies
from chainspacecontract.examples.hello import contract as hello_contract
contract.register_dependency(hello_contract)

import time

####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
	return {
	    'outputs': (dumps({'type' : 'CoCoToken'}),),
	}

# ------------------------------------------------------------------
# create
# NOTE:
#   - sig is an aggregated sign on the hash of the instance object
# ------------------------------------------------------------------
@contract.method('create')
def create(inputs, reference_inputs, parameters, q, t, n, callback, aggr_vk):
    # new petition object
    instance = {
        'type' : 'CoCoInstance',
        'q' : q,
        't' : t,
        'n' : n,
        'callback' : callback,
        'verifier' : pack(aggr_vk)
    }

    ## should create a signature over 'instance'

    # return
    return {
        'outputs': (inputs[0], dumps(instance)),
    }

# ------------------------------------------------------------------
# request
# NOTE: 
#	- args are the arguments for the callback
# ------------------------------------------------------------------
@contract.method('request')
def request(inputs, reference_inputs, parameters, public_m, private_m, gamma, *args):
    # execute PrepareMixSign
    q = loads(inputs[0])['q']
    params = setup(q)
    (cm, c, pi_s) = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

    # new petition object
    request = {
        'type' : 'CoCoRequest',
        'instance' : loads(inputs[0]),
        'public_m' : pack(public_m),
        'cm' : pack(cm),
        'c' : [pack(ci) for ci in c],
        'sigs' : [],
        'pi_s' : pack(pi_s),
        'gamma' : pack(gamma)
    }

    # create dependency
    # @Mustafa: we need to modify the framework to make possible to pass a callback here;
    # i.e., make possible to execute callback_function(args) for any function passed as argument
    hello_contract.init(args)

    # return
    return {
		'outputs': (inputs[0], dumps(request)),
	}

# ------------------------------------------------------------------
# issue
# ------------------------------------------------------------------
@contract.method('issue')
def issue(inputs, reference_inputs, parameters, sk, index):
    # extract data
    request = loads(inputs[0])
    updated_request = loads(inputs[0])
    instance = request['instance']
    q = instance['q']
    params = setup(q)
    cm = unpack(request['cm'])
    c = [unpack(packed_ci) for packed_ci in request['c']]
    public_m = unpack(request['public_m'])
    pi_s = unpack(request['pi_s'])
    gamma = unpack(request['gamma'])

    # sign
    sigma_tilde = blind_sign(params, sk, cm, c, gamma, pi_s, public_m=public_m)

    # update request
    # NOTE: indexes are used to re-order the signature for threshold aggregation
    packet = (index, pack(sigma_tilde))
    updated_request['sigs'].append(packet)

    # return
    return {
        'outputs': (dumps(updated_request),),
        'extra_parameters' : (packet,)
    }


# ------------------------------------------------------------------
# verify
# ------------------------------------------------------------------
@contract.method('verify')
def verify(inputs, reference_inputs, parameters, public_m, private_m):
    # load instance
    instance = loads(reference_inputs[0])

    # build proof
    params = setup(instance['q'])
    aggr_vk = unpack(instance['verifier'])
    sig = unpack(parameters[0])
    (kappa, nu, pi_v) = show_blind_sign(params, aggr_vk, sig, private_m)

    # returns
    return {
        'returns': (dumps(True),),
        'extra_parameters' : (dumps(public_m), pack(kappa), pack(nu), pack(pi_v))
    }


####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check create
# ------------------------------------------------------------------
@contract.checker('create')
def create_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve instance
        instance = loads(outputs[1])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if inputs[0] != outputs[0]: return False
        if instance['type'] != 'CoCoInstance': return False

        # check fields
        q = instance['q'] 
        t = instance['t'] 
        n = instance['n']
        instance['callback']
        packed_vk = instance['verifier']
        if q < 1 or n < 1 or t > n: return False
   
        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check request issue
# ------------------------------------------------------------------
@contract.checker('request')
def request_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve instance
        instance = loads(outputs[0])
        request = loads(outputs[1])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if request['type'] != 'CoCoRequest': return False

        # check fields
        request['public_m']
        params = setup(instance['q'])
        cm = unpack(request['cm'])
        c = [unpack(ci) for ci in request['c']]
        if inputs[0] != outputs[0] or loads(inputs[0]) != request['instance']: return False
        if request['sigs']: return False
        
        # optional: verify proof (could be done locally by each signer)
        pi_s = unpack(request['pi_s'])
        gamma = unpack(request['gamma'])
        if not verify_pi_s(params, gamma, c, cm, pi_s): return False

        # verify depend transaction -- specified by 'callback'
        # NOTE: the checker of the dependency is automatcally called
        callback = dependencies[0]
        if callback['contractID']+'.'+callback['methodID'] != instance['callback']: return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check issue
# ------------------------------------------------------------------
@contract.checker('issue')
def issue_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
    	# retrieve data
        old_request = loads(inputs[0])
        new_request = loads(outputs[0])
        old_sigs = old_request.pop('sigs', None)
        new_sigs = new_request.pop('sigs', None)
        added_sig = parameters[0]

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 

        # check fields
        if old_request != new_request: return False

        # check signature add
      	if new_sigs != old_sigs + [added_sig]: return False

      	## Optional: 
      	## We could verify the partial signature using the vk of each authority (to include in the 'instance' object).
      	## If we do so, the size of the object will increse by a group element for each authority.
      	
        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check issue
# ------------------------------------------------------------------
@contract.checker('verify')
def verify_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve data
        instance = loads(reference_inputs[0])

        # check format
        if len(inputs) != 0 or len(reference_inputs) != 1 or len(outputs) != 0 or len(returns) != 1:
            return False 

        # verify signature
        params = setup(instance['q'])
        packed_sig = parameters[0]
        sig = unpack(parameters[0])
        public_m = loads(parameters[1])
        kappa = unpack(parameters[2])
        nu = unpack(parameters[3])
        pi_v = unpack(parameters[4])
        aggr_vk = unpack(instance['verifier'])
        if not blind_verify(params, aggr_vk, sig, kappa, nu, pi_v, public_m=public_m): return False

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