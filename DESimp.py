from collections import deque
import argparse

shiftab = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

rightshiftab= [0,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def getpermtab(table):
	f = open(table)
	#Returns the permutation table as a list
	return f.readline().split() 

def permutate(ipblock,permtab):
	opblock = ""
	for pos in permtab:
		opblock += ipblock[int(pos)-1]
	return opblock

def text_to_bin(text):
	return bin(int.from_bytes(text.encode(), 'big'))[2:].zfill(64)

def bin_to_text(bin):
	n = int('0b'+bin,2)
	return n.to_bytes((n.bit_length() + 7) // 8,'big').decode()
	
def readable(bin):
	x = '0'
	cnt = 0
	for bit in bin:
		if(x == bit):
			cnt = cnt + 1;
		else:
			print(x,cnt)
			x = bit
			cnt = 1
	print(x,cnt)
	
def XOR(a,b):
	c = ""
	for i in range(len(a)):
		if(a[i] == b[i]):
			c += '1'
		else:
			c += '0'
	
	return c
	
def shiftkey(key,round):
	kr = key[28:]
	lr = key[:28]
	
	shift = -shiftab[round]
	d = deque(kr)
	d.rotate(shift)
	kr = "".join(d)
	d = deque(lr)
	d.rotate(shift)
	lr = "".join(d)
	return(lr + kr)

def rightshiftkey(key,round):
	kr = key[28:]
	lr = key[:28]
	
	shift = rightshiftab[round]
	d = deque(kr)
	d.rotate(shift)
	kr = "".join(d)
	d = deque(lr)
	d.rotate(shift)
	lr = "".join(d)
	return(lr + kr)
	
parser =  argparse.ArgumentParser()
parser.add_argument("plaintext", help="Enter the plaintext to convert to ciphertext")
parser.add_argument("key", help="Enter the key")
args = parser.parse_args()

pt = text_to_bin(args.plaintext)
key = text_to_bin(args.key)

initpermtable = getpermtab("initperm.txt")
ip = permutate(pt,initpermtable)
r0 = ip[32:]
l0 = ip[:32]	

keypermtable = getpermtab("keyperm.txt")
subkey56 = permutate(key,keypermtable)

print("Plaintext : ",pt)
print("Initial Permutation : ",ip)
#print("L0 : ", l0)
#print("r0 : ", r0)
print("Key :           ", key)
print("56-bit subkey : ", subkey56)
for i in range(16):

	subkey56 = shiftkey(subkey56,i)
	#print ("56-bit subkey : ",subkey56)

	compresstable = getpermtab("compressionperm.txt")
	compkey = permutate(subkey56,compresstable)
	#print("compressed key: ",compkey)

	expermtable = getpermtab("expansionperm.txt")
	experm = permutate(r0,expermtable)
	#print("Experm        : ",experm)
	sboxip = XOR(experm,compkey)
	#print("s-box ip      : ",sboxip)
	sboxop = ""
	
	f = open("sboxes.txt")
	for j in range(8):
		sbox = f.readline().split()
		s = sboxip[(6*j):6*(j+1)]
		row = s[0] + s[5]
		column = s[1] + s[2] + s[3] + s[4] 
		index = row + column
		sboxop += bin(int(sbox[int(index,2)]))[2:].zfill(4)
		
	f.close()

	#print("S-box op      : ",sboxop)

	pbox = getpermtab("pbox.txt")
	pboxperm = permutate(sboxop,pbox)
	#print("P-box op      : ",pboxperm)
	r1 = XOR(pboxperm,l0)
	l1 = r0
	#print("l0            : ",l0)
	#print("r1            : ",r1)
	#print("l1            : ",l1)
	r0 = r1
	l0 = l1


finalpermip = r0 + l0
fpermtab = getpermtab("finalperm.txt")
ct = permutate(finalpermip,fpermtab)

print("Cipher text : ",ct)
print("Length : ",len(ct))
print("Cipher text : ", bin_to_text(ct))

initpermtable = getpermtab("initperm.txt")
ip = permutate(ct,initpermtable)

r0 = ip[32:]
l0 = ip[:32]	

for i in range(16):

	subkey56 = rightshiftkey(subkey56,i)
	#print ("56-bit subkey : ",subkey56)

	compresstable = getpermtab("compressionperm.txt")
	compkey = permutate(subkey56,compresstable)
	#print("compressed key: ",compkey)

	expermtable = getpermtab("expansionperm.txt")
	experm = permutate(r0,expermtable)
	#print("Experm        : ",experm)
	sboxip = XOR(experm,compkey)
	#print("s-box ip      : ",sboxip)
	sboxop = ""
	
	f = open("sboxes.txt")
	for i in range(8):
		sbox = f.readline().split()
		s = sboxip[(6*i):6*(i+1)]
		row = s[0] + s[5]
		column = s[1] + s[2] + s[3] + s[4] 
		index = row + column 
		sboxop += bin(int(sbox[int(index,2)]))[2:].zfill(4)
		
	f.close()

	#print("S-box op      : ",sboxop)

	pbox = getpermtab("pbox.txt")
	pboxperm = permutate(sboxop,pbox)
	#print("P-box op      : ",pboxperm)

	r1 = XOR(pboxperm,l0)
	l1 = r0
	#print("l0            : ",l0)
	#print("r1            : ",r1)
	#print("l1            : ",l1)
	r0 = r1
	l0 = l1
	
finalpermip = r0 + l0
fpermtab = getpermtab("finalperm.txt")
ct = permutate(finalpermip,fpermtab)

print("Plain text : ",ct)
print("Length : ",len(ct))
print("Plaintext : ",bin_to_text(ct))