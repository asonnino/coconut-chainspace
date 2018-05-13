from bplib.bp import G2Elem, G1Elem
from petlib.ec import EcGroup
from petlib.pack import encode, decode
from binascii import hexlify, unhexlify

def pet_setup():
	G = EcGroup()
	g = G.generator()
	hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
	o = G.order()
	return (G, g, hs, o)

def pack(x):
    return hexlify(encode(x))

def unpack(x):
    return decode(unhexlify(x))