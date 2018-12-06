from coconut.utils import *
from coconut.proofs import *
from chainspacecontract.examples.utils import *


def make_proof_zeta(params, aggr_vk, sigma, private_m, bind_m=[]):
    """ make commit zeta """
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, beta) = aggr_vk
    (h, s) = sigma
    assert len(private_m) <= len(beta)

    ## material
    r_prime = o.random()
    (h_prime , s_prime) = (r_prime*h , r_prime*s)
    sigma_prime = (h_prime, s_prime)
    t = o.random()
    kappa = t*g2 + alpha + ec_sum([private_m[i]*beta[i] for i in range(len(private_m))])
    nu = t*h_prime
    zeta = private_m[0]*g1

    ## proof
    # create the witnesses
    wm = [o.random() for _ in private_m]
    wt = o.random()
    # compute the witnesses commitments
    Aw = wt*g2 + alpha + ec_sum([wm[i]*beta[i] for i in range(len(private_m))])
    Bw = wt*h_prime
    Cw = wm[0]*g1
    # create the challenge
    bind = [item*g1 for item in bind_m]
    c = to_challenge([g1, g2, alpha, Aw, Bw, Cw]+hs+beta+bind)
    # create responses
    rm = [(wm[i] - c*private_m[i]) % o for i in range(len(private_m))]
    rt = wt - c*t % o
    pi_commit = (c, rm, rt)
    Theta = (kappa, nu, sigma_prime, pi_commit)

    ## output
    return (Theta, zeta)


def verify_proof_zeta(params, aggr_vk, Theta, zeta, public_m=[], bind_m=[]):
    """ verify commit zeta """
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, beta) = aggr_vk
    (kappa, nu, sigma, pi_commit) = Theta
    (h, s) = sigma
    (c, rm, rt) = pi_commit
    private_m_len = len(pi_commit[1])
    assert len(public_m)+private_m_len <= len(beta)

    ## verify proof
    # re-compute witnesses commitments
    Aw = c*kappa + rt*g2 + (1-c)*alpha + ec_sum([rm[i]*beta[i] for i in range(len(rm))])
    Bw = c*nu + rt*h
    Cw = rm[0]*g1 + zeta*c
    # compute the challenge prime
    bind = [item*g1 for item in bind_m]
    assert c == to_challenge([g1, g2, alpha, Aw, Bw, Cw]+hs+beta+bind)

    ## verify signature
    # add clear text messages
    aggr = G2Elem.inf(G)
    if len(public_m) != 0:
        aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
    # verify
    return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)

'''
def verify_proof_zeta_bind(params, aggr_vk, Theta, zeta, public_m=[], bind_m=[]):
    """ verify reveal zeta """
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, beta) = aggr_vk
    (kappa, nu, sigma, pi_commit) = Theta
    (h, s) = sigma
    (c, rm, rt) = pi_commit
    private_m_len = len(pi_commit[1])
    assert len(public_m)+private_m_len <= len(beta)
    
    ## verify proof
    # re-compute witnesses commitments
    Aw = c*kappa + rt*g2 + (1-c)*alpha + ec_sum([rm[i]*beta[i] for i in range(len(rm))])
    Bw = c*nu + rt*h
    Cw = rm[0]*g1 + zeta*c
    # compute the challenge prime
    bind = [item*g1 for item in bind_m]
    assert c == to_challenge([g1, g2, alpha, Aw, Bw, Cw]+hs+beta+bind)
    
    ## verify signature
    # add clear text messages
    aggr = G2Elem.inf(G)
    if len(public_m) != 0:
        aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
    # verify
    return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)
'''

