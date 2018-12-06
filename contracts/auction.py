""" Auction contract """


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
from chainspacecontract.examples.auction_proofs import *
from coconut.utils import *
from coconut.scheme import *
# chainspace
from chainspacecontract import ChainspaceContract

## contract name
contract = ChainspaceContract('auction')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'AToken'}),),
    }

# ------------------------------------------------------------------
# create
# ------------------------------------------------------------------
@contract.method('create')
def create(inputs, reference_inputs, parameters, aggr_vk, t_commit, t_reveal, uid, v0, ov0):
    
    # commitment to the minim price
    (G, o, g1, hs, g2, e) = setup()
    cv0 = g1*v0 + hs[0]*ov0
    
    # auction object
    auction = {
        'type' : 'Auction',
        'list' : [],
        'vk'  : pack(aggr_vk),
        't_commit' : t_commit,
        't_reveal' : t_reveal,
        'uid' : uid,
        'cv0' : pack(cv0),
        'file_hash' : ''
    }

    # return
    return {
        'outputs': (inputs[0], dumps(auction)),
    }

# ------------------------------------------------------------------
# commit
# ------------------------------------------------------------------
@contract.method('commit')
def commit(inputs, reference_inputs, parameters, seq, v, sigma):
    auction = loads(inputs[0])
    aggr_vk = unpack(auction['vk'])
    
    # auction object
    bp_params = setup(2)
    private_m = [seq, v]
    (Theta, zeta) = make_proof_zeta(bp_params, aggr_vk, sigma, private_m)
    auction['list'].append(pack(zeta))
    #assert verify_proof_zeta(bp_params, aggr_vk, Theta, zeta)
    
    # return
    return {
        'outputs': (dumps(auction),),
        'extra_parameters' : (pack(Theta), pack(zeta)),
    }

# ------------------------------------------------------------------
# reveal
# ------------------------------------------------------------------
@contract.method('reveal')
def reveal(inputs, reference_inputs, parameters, seq, sigma):
    auction = loads(inputs[0])
    aggr_vk = unpack(auction['vk'])
    v = loads(parameters[0])
    
    # auction object
    bp_params = setup(2)
    private_m = [seq]
    (Theta, zeta) = make_proof_zeta(bp_params, aggr_vk, sigma, private_m)
    #assert verify_proof_zeta(bp_params, aggr_vk, Theta, zeta, public_m=[v])
    packet = (v, pack(zeta))
    auction['list'] = [packet if x==pack(zeta) else x for x in auction['list']]
    
    # return
    return {
        'outputs': (dumps(auction),),
        'extra_parameters' : (pack(Theta), pack(zeta)),
}

# ------------------------------------------------------------------
# withdraw
# ------------------------------------------------------------------
@contract.method('withdraw')
def withdraw(inputs, reference_inputs, parameters, seq, sigma):
    auction = loads(inputs[0])
    aggr_vk = unpack(auction['vk'])
    v = loads(parameters[0])
    addr = unpack(parameters[1])
    
    # auction object
    bp_params = setup(2)
    private_m = [seq]
    bind_m = [addr]
    (Theta, zeta) = make_proof_zeta(bp_params, aggr_vk, sigma, private_m, bind_m=bind_m)
    #assert verify_proof_zeta(bp_params, aggr_vk, Theta, zeta, public_m=[v], bind_m=bind_m)
    packet = (v, pack(zeta))
    auction['list'] = [None if x==list(packet) else x for x in auction['list']]

    # return
    return {
        'outputs': (dumps(auction),),
        'extra_parameters' : (pack(Theta), pack(zeta)),
    }

# ------------------------------------------------------------------
# submitWork
# ------------------------------------------------------------------
@contract.method('submitWork')
def submitWork(inputs, reference_inputs, parameters, seq, sigma):
    auction = loads(inputs[0])
    aggr_vk = unpack(auction['vk'])
    v = loads(parameters[0])
    file_hash = unpack(parameters[1])
    
    # auction object
    bp_params = setup(2)
    private_m = [seq]
    bind_m = [file_hash]
    (Theta, zeta) = make_proof_zeta(bp_params, aggr_vk, sigma, private_m, bind_m=bind_m)
    #assert verify_proof_zeta(bp_params, aggr_vk, Theta, zeta, public_m=[v], bind_m=bind_m)
    auction['file_hash'] = parameters[1]
    
    # return
    return {
        'outputs': (dumps(auction),),
        'extra_parameters' : (pack(Theta), pack(zeta)),
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
        # retrieve object
        auction = loads(outputs[1])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'AToken' or loads(outputs[0])['type'] != 'AToken': return False
        if auction['type'] != 'Auction': return False
        
        # check timestamps
        if auction['t_commit'] <= 0 or auction['t_commit'] >= auction['t_reveal']: return False

        # check fields
        auction['vk']
        auction['uid']
        auction['cv0']
        auction['file_hash']
        if auction['list']: return False # check list is empty

        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check commit
# ------------------------------------------------------------------
@contract.checker('commit')
def commit_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve
        old_auction = loads(inputs[0])
        new_auction = loads(outputs[0])
        vk = unpack(new_auction['vk'])
        Theta = unpack(parameters[0])
        zeta_packed = parameters[1]

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 
       
        # check list
        if (zeta_packed in old_auction['list']) or (new_auction['list'] != old_auction['list'] + [zeta_packed]):
            return False
        
        # check fields
        old_auction['list'], new_auction['list'] = None, None
        if old_auction != new_auction: return False

        # verify proof
        bp_params = setup(2)
        zeta = unpack(zeta_packed)
        if not verify_proof_zeta(bp_params, vk, Theta, zeta): return False

        # otherwise
        return True

    except (KeyError, Exception): 
        return False

# ------------------------------------------------------------------
# check reveal
# ------------------------------------------------------------------
@contract.checker('reveal')
def reveal_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve
        old_auction = loads(inputs[0])
        new_auction = loads(outputs[0])
        vk = unpack(new_auction['vk'])
        v = loads(parameters[0])
        Theta = unpack(parameters[1])
        zeta_packed = parameters[2]

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False
        
        # check list
        if zeta_packed not in old_auction['list']: return False
        packet = (v, zeta_packed)
        for i in range(len(old_auction['list'])):
            if old_auction['list'][i] == zeta_packed:
                old_auction['list'][i] = list(packet)
                break # ensure that only one element is modified
        if (new_auction['list'] != old_auction['list']): return False
        
        # check fields
        old_auction['list'], new_auction['list'] = None, None
        if old_auction != new_auction: return False

        # verify proof
        bp_params = setup(2)
        zeta = unpack(zeta_packed)
        if not verify_proof_zeta(bp_params, vk, Theta, zeta, public_m=[v]): return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check withdraw
# NOTE: if multiple biggest bids, the first bidder wins
# ------------------------------------------------------------------
@contract.checker('withdraw')
def withdraw_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve
        old_auction = loads(inputs[0])
        new_auction = loads(outputs[0])
        vk = unpack(new_auction['vk'])
        v = loads(parameters[0])
        addr = unpack(parameters[1])
        Theta = unpack(parameters[2])
        zeta_packed = parameters[3]
        
        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False
        
        # check list
        packet = (v, zeta_packed)
        if list(packet) not in old_auction['list']: return False
        for i in range(len(old_auction['list'])):
            if old_auction['list'][i] == list(packet):
                old_auction['list'][i] = None
                break # ensure that only one element is modified
        if (new_auction['list'] != old_auction['list']): return False

        # winner cannot withdraw fundings
        max_item = max([item for item in old_auction['list']]) # get first biggest item
        if list(packet) == max_item: return False

        # check fields
        old_auction['list'], new_auction['list'] = None, None
        if old_auction != new_auction: return False

        # verify proof
        bp_params = setup(2)
        zeta = unpack(zeta_packed)
        if not verify_proof_zeta(bp_params, vk, Theta, zeta, public_m=[v], bind_m=[addr]): return False
        
        # otherwise
        return True

    except (KeyError, Exception):
        return False

# ------------------------------------------------------------------
# check submitWork
# ------------------------------------------------------------------
@contract.checker('submitWork')
def submitWork_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve
        old_auction = loads(inputs[0])
        new_auction = loads(outputs[0])
        vk = unpack(new_auction['vk'])
        v = loads(parameters[0])
        file_hash_packed = parameters[1]
        Theta = unpack(parameters[2])
        zeta_packed = parameters[3]

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0: return False
        
        # check list
        if old_auction['file_hash'] != '': return False
        if new_auction['file_hash'] != file_hash_packed: return False
        
        # only winner can submit file hash
        max_item = max([item for item in old_auction['list']]) # get first biggest item
        packet = (v, zeta_packed)
        if list(packet) != max_item: return False
        
        # check fields
        old_auction['file_hash'], new_auction['file_hash'] = None, None
        if old_auction != new_auction: return False
        
        # verify proof
        bp_params = setup(2)
        zeta = unpack(zeta_packed)
        file_hash = unpack(file_hash_packed)
        if not verify_proof_zeta(bp_params, vk, Theta, zeta, public_m=[v], bind_m=[file_hash]): return False
        
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
