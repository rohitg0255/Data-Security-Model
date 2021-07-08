import random

def GeneratePQ():#generate large prime p and q
    p=random.randint(10,100)
    q=random.randint(10,100)
    while (IsPrime(p)!=True) and (IsPrime(q)!=True) and (p!=q):
        p=random.randint(10,100)
        q=random.randint(10,100)
    return p,q
        
def IsPrime(num): #primality test for p and q
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True
def GCD(a,b):    #checks whether e and phi are coprime
    while(b!=0):
        a,b=b,a%b
    return a
 #generates private key(n,d) using extended euclidean algorithm
def MultiplicativeInverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2- temp1* x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi

def GenerateKeyPair():
    p,q=GeneratePQ()
    n = p * q
    phi = (p-1) * (q-1) #Phi is the totient of n    
    e = random.randrange(1, phi)    #Choose an integer e such that e and phi(n) are coprime
    g = GCD(e, phi)    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    while g != 1:
        e = random.randrange(1, phi)
        g = GCD(e, phi)
    d = MultiplicativeInverse(e, phi)     #Use Extended Euclid's Algorithm to generate the private key   
    with open('public.txt','w') as pu:
        pu.write("%s\n" %n)
        pu.write("%s\n" %e)
    with open('private.txt','w') as pu:
        pu.write("%s\n" %n)
        pu.write("%s\n" %d)
    return ((n,e), (n,d))   #Return public key ( n,e) and private key (n,d)
    
