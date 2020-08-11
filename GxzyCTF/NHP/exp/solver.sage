# input: q, r_s, s_s, Hm_s
import json

t = 40

# Load data
f = open("data", "r")
(q, Hm_s, r_s, s_s) = json.load(f)


# Calculate A & B
A = []
B = []
for r, s, Hm in zip(r_s, s_s, Hm_s):
    A.append( ZZ( (inverse_mod(s, q)*r) % q ) )
    B.append( ZZ( (inverse_mod(s, q)*Hm) % q ) )


# Construct Lattice
K = 2^122   # k < 2^122
X = q * identity_matrix(QQ, t) # t * t
Z = matrix(QQ, [0] * t + [K/q] + [0]).transpose() # t+1 column
Z2 = matrix(QQ, [0] * (t+1) + [K]).transpose()    # t+2 column

Y = block_matrix([[X],[matrix(QQ, A)], [matrix(QQ, B)]]) # (t+2) * t
Y = block_matrix([[Y, Z, Z2]])

# Find short vector
Y = Y.LLL()

# check
k0 = ZZ(Y[1, 0] % q)
x = ZZ(Y[1, -2] / (K/q) % q)
assert(k0 == (A[0]*x + B[0]) % q)
print x