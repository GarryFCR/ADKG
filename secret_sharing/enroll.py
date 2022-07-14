import math, secrets, itertools

#p = 11
p = 13
d = 2
def f(x, p):
    #return (6 + 4*x + 9*x*x + 6*x*x*x) % p
    return (9 + 2*x + 5*x*x) % p

s=[]
#n=4
n=3
nodes = list(range(1, n+1))
new_node = n+1 # MIGHT WANT TO MAKE SHA?
s = [f(i,p) for i in nodes]

# generate lagrange coefficients product
gamma=[int(math.prod((new_node - j)/(i - j) for j in nodes if i!=j))%p for i in nodes]

# split f(i)*lagrange into random sub-shares
r = [xs+[(s_i*gamma_i - sum(xs)) % p] for (xs, s_i, gamma_i) in zip([[secrets.randbelow(p) for _ in nodes[1:]] for _ in nodes], s, gamma)]
assert sum([(sum(xs) - s_i*gamma_i)%p for (xs, s_i, gamma_i) in zip(r, s, gamma)]) == 0, f'r is not a correct split of the secret evaluations!'

# share the sub-shares to the correct nodes
rT = [list(xs) for xs in zip(*r)]

# each node joins their own sub-shares
sigma = [sum(xs) % p for xs in rT]

# the new node joins intermediate values
output = sum(sigma) % p





print(f'nodes: {list(nodes)}, n: {n}, p: {p}, new_node: {new_node}')
print(f's: {s}')
print(f'gamma: {gamma}')
print(f's_i*gamma_i: {[(s_i*gamma_i)%p for s_i, gamma_i in zip(s, gamma)]}')
print(f'r: {r}')
print(f'rT: {rT}')

print(f'sigma: {sigma}')
print(f'output: {output}')
f_new = f(new_node, p)
print(f'f_new: {f_new}')
assert output==f_new, f'did not correctly evaluate the chosen point ({new_node}).'

s.append(output)
nodes.append(new_node)

#print(f'f_?: {[f(i, p) for i in range(1, n+10)]}')


################################ DISENROLL
# protocol essentially used to obsolete invalid shares, to ensure they can no longer be used in the recovery protocol

old_node = 2
good_nodes = [x for x in nodes if x!=old_node] # NEEDS CONSENSUS
assert new_node != old_node, f'there\'s no point disenrolling a node with the same share as the one being repaired'

# generate new random zero-polynomials
gs = {node:[0 if i==0 else secrets.randbelow(p) for i in range(d+1)] for node in good_nodes}

# generate new additive shares
ss = 

def g(coefficients, x, p):
    return sum([a*x**i for i, a in enumerate(coefficients)]) % p
