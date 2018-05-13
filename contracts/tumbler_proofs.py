from coconut.utils import *
from coconut.proofs import *
from chainspacecontract.examples.utils import *


def make_proof_tumbler(params, aggr_vk, sigma, ID, addr):
	""" build material & proof for coconut showing """
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	private_m = [ID, addr]
	assert len(private_m) <= len(beta)

	## material
	t = o.random()
	kappa = t*g2 + alpha + ec_sum([private_m[i]*beta[i] for i in range(len(private_m))])
	nu = t*h
	zeta = private_m[0]*g1

	## proof
	# create the witnesses
	wm = [o.random() for _ in private_m]
	wt = o.random()
	# compute the witnesses commitments
	Aw = wt*g2 + alpha + ec_sum([wm[i]*beta[i] for i in range(len(private_m))])
	Bw = wt*h
	Cw = wm[0]*g1
	# create the challenge
	bind = addr*g1
	c = to_challenge([g1, g2, alpha, Aw, Bw, Cw, bind]+hs+beta)
	# create responses 
	rm = [(wm[i] - c*private_m[i]) % o for i in range(len(private_m))]
	rt = wt - c*t % o
	pi_tumbler = (c, rm, rt)

	## output
	return (kappa, nu, zeta, pi_tumbler)


def verify_proof_tumbler(params, aggr_vk, sigma, kappa, nu, zeta, pi_tumbler, addr, public_m=[]):
	""" verify signature """
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	(c, rm, rt) = pi_tumbler
	private_m_len = len(pi_tumbler[1])
	assert len(public_m)+private_m_len <= len(beta)

	## verify proof
	# re-compute witnesses commitments
	Aw = c*kappa + rt*g2 + (1-c)*alpha + ec_sum([rm[i]*beta[i] for i in range(len(rm))])
	Bw = c*nu + rt*h
	Cw = rm[0]*g1 + zeta*c
	# compute the challenge prime
	bind = addr*g1
	assert c == to_challenge([g1, g2, alpha, Aw, Bw, Cw, bind]+hs+beta)

	## verify signature
	# add clear text messages
	aggr = G2Elem.inf(G) 
	if len(public_m) != 0:
		aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
	# verify
	return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)


