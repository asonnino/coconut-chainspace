""" 
	A simple smart contract illustarting an e-petition.
"""


####################################################################
# imports
####################################################################
# general
from hashlib import sha256
from json    import dumps, loads
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
# coconut
from chainspacecontract.examples.utils import *
from chainspacecontract.examples.petition_proofs import *
from coconut.utils import *
from coconut.scheme import *

# chainspace
from chainspacecontract import ChainspaceContract

## contract name
contract = ChainspaceContract('petition')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'PToken'}),),
    }

# ------------------------------------------------------------------
# create petition
# ------------------------------------------------------------------
@contract.method('create_petition')
def create_petition(inputs, reference_inputs, parameters, UUID, options, priv_owner, pub_owner, aggr_vk):
    # inital score
    pet_params = pet_setup()
    (G, g, hs, o) = pet_params
    zero = (G.infinite(), G.infinite())
    scores = [pack(zero), pack(zero)]

    # new petition object
    new_petition = {
        'type' : 'PObject',
        'UUID' : pack(UUID), # unique ID of the petition
        'owner' : pack(pub_owner), # entity creating the petition
        'verifier' : pack(aggr_vk), # entity delivering credentials to participate to the petition
        'options' : options, # the options
        'scores' : scores # the signatures per option
    }

    # ID lists
    signed_list = {
        'type' : 'PList',
        'list' : []
    }

    # signature
    hasher = sha256()
    hasher.update(dumps(new_petition).encode('utf8'))
    sig = do_ecdsa_sign(pet_params[0], priv_owner, hasher.digest())

    # return
    return {
        'outputs': (inputs[0], dumps(new_petition), dumps(signed_list)),
        'extra_parameters' : (pack(sig),)
    }

# ------------------------------------------------------------------
# sign
# ------------------------------------------------------------------
@contract.method('sign')
def sign(inputs, reference_inputs, parameters, priv_signer, sig, aggr_vk, vote):
    # ini petition, list and parameters
    old_petition = loads(inputs[0])
    new_petition = loads(inputs[0])
    old_list = loads(inputs[1])
    new_list = loads(inputs[1])

    # prepare showing of credentials
    UUID = unpack(old_petition['UUID'])
    bp_params = setup()
    (kappa, nu, zeta, pi_petition) = make_proof_credentials_petition(bp_params, aggr_vk, sig, [priv_signer], UUID)
    #assert verify_proof_credentials_petition(bp_params, aggr_vk, sig, kappa, nu, zeta, pi_petition, UUID)

    # update spent list
    new_list['list'].append(pack(zeta))

    # encrypt the votes 
    pub_owner = unpack(old_petition['owner'])
    pet_params = pet_setup()
    (enc_v, enc_v_not, cv, pi_vote) = make_proof_vote_petition(pet_params, pub_owner, vote) 
    #assert verify_proof_vote_petition(pet_params, enc_v, pub_owner, cv, pi_vote)

    # update petition values
    old_enc_v = unpack(old_petition['scores'][0])
    old_enc_v_not = unpack(old_petition['scores'][1])
    new_enc_v = (old_enc_v[0] + enc_v[0], old_enc_v[1] + enc_v[1])
    new_enc_v_not = (old_enc_v_not[0] + enc_v_not[0], old_enc_v_not[1] + enc_v_not[1])
    new_petition['scores'] = [pack(new_enc_v), pack(new_enc_v_not)]

    # return
    return {
        'outputs': (dumps(new_petition),dumps(new_list)),
        'extra_parameters' : (pack(sig), pack(kappa), pack(nu), pack(zeta), pack(pi_petition), 
            pack(enc_v), pack(cv), pack(pi_vote))
    }



####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check petition's creation
# ------------------------------------------------------------------
@contract.checker('create_petition')
def create_petition_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve petition
        petition = loads(outputs[1])
        # retrieve ID list
        spent_list = loads(outputs[2])
        # retrieve parameters
        sig = unpack(parameters[0])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 3 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'PToken' or loads(outputs[0])['type'] != 'PToken': return False
        if petition['type'] != 'PObject' or spent_list['type'] != 'PList': return False

        # check fields
        petition['UUID'] # check presence of UUID
        petition['verifier'] # check presence of verifier
        options = petition['options']
        scores = petition['scores'] 
        pub_owner = unpack(petition['owner'])
        if len(options) < 1 or len(options) != len(scores): return False

        # check initalised scores
        pet_params = pet_setup()
        (G, g, hs, o) = pet_params
        zero = (G.infinite(), G.infinite())
        if not all(init_score==pack(zero) for init_score in scores): return False

        # verify signature
        hasher = sha256()
        hasher.update(outputs[1].encode('utf8'))
        if not do_ecdsa_verify(pet_params[0], pub_owner, sig, hasher.digest()): return False

        # verify that the spent list is empty
        if spent_list['list']: return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False


# ------------------------------------------------------------------
# check add score
# ------------------------------------------------------------------
@contract.checker('sign')
def sign_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        
        # retrieve petition
        old_petition = loads(inputs[0])
        new_petition = loads(outputs[0])
        # retrieve ID list
        old_list = loads(inputs[1])
        new_list = loads(outputs[1])
        # retrieve parameters
        bp_params = setup()
        sig = unpack(parameters[0])
        kappa = unpack(parameters[1])
        nu = unpack(parameters[2])
        zeta = unpack(parameters[3])
        pi_petition = unpack(parameters[4])
        enc_v = unpack(parameters[5])
        cv = unpack(parameters[6])
        pi_vote = unpack(parameters[7])
        
        # check format
        if len(inputs) != 2 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if new_petition['type'] != 'PObject' or new_list['type'] != 'PList': return False      

        # check format & consistency with old object
        UUID = unpack(new_petition['UUID'])
        options = new_petition['options']
        packed_vk = new_petition['verifier']
        scores = new_petition['scores']
        if old_petition['UUID'] != new_petition['UUID']: return False
        if len(old_petition['owner']) != len(new_petition['owner']): return False
        if len(old_petition['options']) != len(new_petition['options']): return False
        if old_petition['verifier'] != new_petition['verifier']: return False

        # re-compute opposite of vote encryption
        pet_params = pet_setup()
        (G, g, hs, o) = pet_params
        (a, b) = enc_v
        enc_v_not = (-a, -b + hs[0])

        # check homomorphic add
        old_enc_v = unpack(old_petition['scores'][0])
        old_enc_v_not = unpack(old_petition['scores'][1])
        new_enc_v = (old_enc_v[0] + enc_v[0], old_enc_v[1] + enc_v[1])
        new_enc_v_not = (old_enc_v_not[0] + enc_v_not[0], old_enc_v_not[1] + enc_v_not[1])
        if not new_petition['scores'] == [pack(new_enc_v), pack(new_enc_v_not)]: return False

        # check new values
        pub_owner = unpack(old_petition['owner'])
        if not  verify_proof_vote_petition(pet_params, enc_v, pub_owner, cv, pi_vote): return False

        # check double-voting list
        packed_zeta = parameters[3]
        if (packed_zeta in old_list['list']) or (new_list['list'] != old_list['list'] + [packed_zeta]):
            return False
        
        # verify signature
        aggr_vk = unpack(packed_vk)
        if not verify_proof_credentials_petition(bp_params, aggr_vk, sig, kappa, nu, zeta, pi_petition, UUID): 
            return False
  
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