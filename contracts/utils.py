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

def pack_vk(vk):
	#return (pack(vk[0]),pack(vk[1]),[pack(beta_i) for beta_i in vk[2]])
	return pack(vk)

def unpack_vk(params, packed_vk):
	#return (unpackG2(params,packed_vk[0]), unpackG2(params,packed_vk[1]), [unpackG2(params,y) for y in packed_vk[2]])
	return unpack(packed_vk)