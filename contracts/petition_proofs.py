""" Proofs for petition signature """
from bplib.bp import G2Elem
from coconut.utils import *
from coconut.proofs import *
from chainspacecontract.examples.utils import *


def make_proof_credentials_petition(params, aggr_vk, sigma, private_m, UUID):
	""" build material & proof for coconut petition showing """
	assert len(private_m) > 0
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	assert len(private_m) <= len(beta)

	## material
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

	## output
	return (kappa, nu, zeta, pi_petition)

def verify_proof_credentials_petition(params, aggr_vk, sigma, kappa, nu, zeta, pi_petition, UUID, public_m=[]):
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


def make_proof_vote_petition(params, pub, m):
	""" create encryption & proof of vote """
	(G, g, hs, o) = params

	## material
	# vote encryption
	k = o.random()
	enc_v = (k*g, k*pub + m*hs[0])
	# oppposite of vote encryption
	(a, b) = enc_v
	enc_v_not = (-a, -b + hs[0])
	# commitment to the vote
	r1 = o.random()
	r2 = (1-m) * r1
	cv = m*g + r1*hs[0]

	## proof
	# create the witnesses
	wk = o.random()
	wm = o.random()
	wr1 = o.random()
	wr2 = o.random()
	# compute the witnesses commitments
	Aw = wk*g
	Bw = wk*pub + wm*hs[0]
	Cw = wm*g + wr1*hs[0]
	Dw = wm*cv + wr2*hs[0]
	# create the challenge
	c = to_challenge([g, hs[0], a, b, cv, Aw, Bw, Cw, Dw])
	# create responses
	rk = (wk - c*k) % o
	rm = (wm - c*m) % o
	rr1 = (wr1 - c*r1) % o
	rr2 = (wr2 - c*r2) % o
	pi_vote = (c, (rk, rm, rr1, rr2))

	## output
	return (enc_v, enc_v_not, cv, pi_vote)

def verify_proof_vote_petition(params, enc_v, pub, cv, pi_vote):
	""" verify vote correctness """
	(G, g, hs, o) = params
	(a, b) = enc_v
	(c, (rk, rm, rr1, rr2)) = pi_vote
	# re-compute witnesses commitment
	Aw = rk*g + c*a
	Bw = rk*pub + rm*hs[0] + c*b
	Cw = rm*g + rr1*hs[0] + c*cv
	Dw = rm*cv + rr2*hs[0] + c*cv
	# verify challenge
	return c == to_challenge([g, hs[0], a, b, cv, Aw, Bw, Cw, Dw])


def make_proof_tally_petition(params, li, enc_results, priv):
	""" make proof of correct tally """
	(G, g, hs, o) = params
	# create the witnesses
	wx = o.random()
	# compute the witnesses commitments
	Aw = [(-wx*li*enc[0]) for enc in enc_results]
	# create the challenge
	c = to_challenge([g, hs[0]]+Aw)
	# create responses
	rx = (wx - c*priv) % o
	return (c, rx)

def verify_proof_tally_petition(params, li, enc_results, pi_dec, eta):
	""" verify proof of correct tally """
	(G, g, hs, o) = params
	(c, rx) = pi_dec
	# re-compute witnesses commitment
	Aw = [-rx*li*enc_results[i][0] + c*eta[i] for i in range(len(enc_results))]
	# verify challenge
	return c == to_challenge([g, hs[0]]+Aw)




