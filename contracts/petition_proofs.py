""" Proofs for petition signature """
from bplib.bp import G2Elem
from coconut.utils import *
from coconut.proofs import *


def make_proof_petition(params, aggr_vk, sigma, private_m, UUID):
	""" build material & proof for coconut petition showing """
	## material
	assert len(private_m) > 0
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	assert len(private_m) <= len(beta)
	t = o.random()
	kappa = t*g2 + alpha + ec_sum([private_m[i]*beta[i] for i in range(len(private_m))])
	nu = t*h
	zeta = private_m[0] * G.hashG1(str(UUID))

	## proof
	# create the witnesses
	wm = [o.random() for _ in private_m]
	wt = o.random()
	# compute the witnesses commitments
	Aw = wt*g2 + alpha + ec_sum([wm[i]*beta[i] for i in range(len(private_m))])
	Bw = wt*h
	Cw = wm[0]*G.hashG1(str(UUID))
	# create the challenge
	c = to_challenge([g1, g2, alpha, Aw, Bw, Cw]+hs+beta)
	# create responses 
	rm = [(wm[i] - c*private_m[i]) % o for i in range(len(private_m))]
	rt = wt - c*t % o
	pi_petition = (c, rm, rt)

	return (kappa, nu, zeta, pi_petition)



def verify_proof_petition(params, aggr_vk, sigma, kappa, nu, zeta, pi_petition, UUID, public_m=[]):
	""" verify petition signature """
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	(c, rm, rt) = pi_petition
	private_m_len = len(pi_petition[1])
	assert len(public_m)+private_m_len <= len(beta)

	## verify proof
	# re-compute witnesses commitments
	Aw = c*kappa + rt*g2 + (1-c)*alpha + ec_sum([rm[i]*beta[i] for i in range(len(rm))])
	Bw = c*nu + rt*h
	Cw = rm[0]*G.hashG1(str(UUID)) + zeta*c
	# compute the challenge prime
	assert c == to_challenge([g1, g2, alpha, Aw, Bw, Cw]+hs+beta)

	## verify signature
	# add clear text messages
	aggr = G2Elem.inf(G) 
	if len(public_m) != 0:
		aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
	# verify
	return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)




