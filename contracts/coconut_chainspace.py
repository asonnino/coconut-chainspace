""" Coconut smart contract library """


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
    n = loads(inputs[0])['n']
    params = setup(q)
    Lambda = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

    # new petition object
    request = {
        'type' : 'CoCoRequest',
        'instance' : loads(inputs[0]),
        'public_m' : pack(public_m),
        'Lambda' : pack(Lambda),
        'sigs' : [None] * n,
        'gamma' : pack(gamma)
    }

    # create dependency
    # @all: we need to modify the framework to make possible to pass a callback here;
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
def issue(inputs, reference_inputs, parameters, sk):
    # extract data
    request = loads(inputs[0])
    updated_request = loads(inputs[0])
    instance = request['instance']
    q = instance['q']
    params = setup(q)
    public_m = unpack(request['public_m'])
    gamma = unpack(request['gamma'])
    Lambda = unpack(request['Lambda'])
    index = parameters[0]

    # sign
    sigma_tilde = blind_sign(params, sk, gamma, Lambda, public_m=public_m)
    packed_sigma_tilde = pack(sigma_tilde)
    updated_request['sigs'][index] = packed_sigma_tilde

    # return
    return {
        'outputs': (dumps(updated_request),),
        'extra_parameters' : (packed_sigma_tilde,)
    }


# ------------------------------------------------------------------
# verify
# ------------------------------------------------------------------
@contract.method('verify')
def verify(inputs, reference_inputs, parameters, sig, private_m):
    # load instance
    instance = loads(reference_inputs[0])

    # build proof
    params = setup(instance['q'])
    aggr_vk = unpack(instance['verifier'])
    Theta = prove_cred(params, aggr_vk, sig, private_m)

    # returns
    return {
        'returns': (dumps(True),),
        'extra_parameters' : (pack(Theta),)
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
        Lambda = unpack(request['Lambda'])
        (cm, c, pi_s) = Lambda
        if inputs[0] != outputs[0] or loads(inputs[0]) != request['instance']: return False
        if request['sigs'] != [None] * instance['n']: return False
        
        # optional: verify proof (could be done locally by each signer)
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
        old_sigs = old_request['sigs']
        new_sigs = new_request['sigs']
        index = parameters[0]
        added_sig = parameters[1]

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 

        # check fields
        old_request['sigs'], new_request['sigs'] = None, None
        if old_request != new_request: return False

        # check signature add
        old_sigs[index] = added_sig
        if new_sigs != old_sigs: return False

      	## We could verify the partial signature using the vk of each authority (to include in the 'instance' object). If we do so, the size of the object will increse linearly with the number of authorities. Otherwise we can off-load it to the client.
      	
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
        public_m = loads(parameters[0])
        Theta = unpack(parameters[1])
        aggr_vk = unpack(instance['verifier'])
        if not verify_cred(params, aggr_vk, Theta, public_m=public_m): return False

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
