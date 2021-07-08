import Rsa
#cipher inversion
IPinv=[ 40  ,   8 ,  48  ,  16 ,   56 ,  24 ,   64 ,  32,
            39  ,   7 ,  47   , 15 ,   55  , 23  ,  63  , 31,
            38 ,    6 ,  46  ,  14  ,  54  , 22  ,  62 ,  30,
            37  ,   5 ,  45  ,  13  ,  53 ,  21  ,  61  , 29,
            36  ,   4  , 44 ,   12 ,   52 ,  20 ,   60  , 28,
            35  ,   3 ,  43 ,   11 ,   51 ,  19 ,   59 ,  27,
            34  ,   2 ,  42 ,   10 ,   50 ,  18  ,  58 ,  26,
            33  ,   1 ,  41 ,    9  ,  49 ,  17  ,  57   ,25]   
#R expand matrix to 48 bit
E_BIT_SELECTION =[ 32,     1 ,   2  ,   3 ,    4  ,  5,
                     4   ,  5 ,   6  ,   7  ,   8  ,  9,
                     8  ,   9 ,  10 ,   11  ,  12 ,  13,
                    12  ,  13 ,  14  ,  15 ,   16 ,  17,
                    16  ,  17  , 18 ,   19 ,   20 ,  21,
                    20  ,  21 ,  22  ,  23 ,   24 ,  25,
                    24 ,   25 ,  26  ,  27  ,  28 ,  29,
                    28 ,   29 ,  30  ,  31  ,  32 ,   1]
#inital permutation for 64 bit data
IP = [58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7]                    
#permutation combination for initial 64 bit key
PC_1=[57 ,  49   , 41  , 33  ,  25  ,  17 ,   9,
       1  , 58 ,   50,   42  ,  34 ,   26  , 18,
      10 ,   2  ,  59 ,  51  ,  43  ,  35  , 27,
      19  , 11  ,   3 ,  60 ,   52  ,  44  , 36,
      63  , 55  ,  47 ,  39 ,   31 ,   23  , 15,
       7 ,  62  ,  54 ,  46 ,   38 ,   30  , 22,
      14 ,   6  ,  61 ,  53  ,  45 ,   37 ,  29,
      21  , 13 ,    5 ,  28  ,  20  ,  12 ,   4]
#56 bit key to 48 bit key round subkey
PC_2=[14 ,   17 ,  11  ,  24 ,    1    ,5,
       3 ,   28  , 15 ,    6  ,  21,   10,
      23  ,  19 ,  12 ,    4 ,   26 ,   8,
      16 ,    7 ,  27 ,   20 ,   13 ,   2,
      41 ,   52 ,  31 ,   37 ,   47 ,  55,
      30  ,  40 ,  51 ,   45 ,   33 ,  48,
      44 ,   49 ,  39  ,  56 ,   34 ,  53,
      46 ,   42  , 50  ,  36 ,   29 ,  32]         
#no of leftshift for each 16 round subkey
LeftRotate=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
#S-box substitution
S=[[[14,  4 , 13,  1 ,  2, 15 , 11,  8 ,  3, 10,   6 ,12 ,  5,  9  , 0,  7],
    [0 ,15 ,  7 , 4,  14 , 2 , 13 , 1 , 10 , 6 , 12, 11,   9 , 5  , 3 , 8],
    [4 , 1,  14 , 8 , 13 , 6 ,  2 ,11,  15, 12 ,  9,  7 ,  3 ,10 ,  5 , 0],
    [15, 12 ,  8 , 2 ,  4 , 9,   1 , 7 ,  5 ,11,   3 ,14 , 10 , 0 ,  6 ,13]],
   [[15,  1 ,  8, 14 ,  6 ,11 ,  3 , 4 ,  9 , 7 ,  2 ,13 , 12 , 0 ,  5 ,10],
     [ 3 ,13,   4 , 7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9 , 11 , 5],
     [ 0, 14,   7 ,11,  10 , 4,  13,  1 ,  5 , 8,  12,  6 ,  9 , 3  , 2 ,15],
     [13,  8 , 10 , 1,   3 ,15 ,  4,  2  ,11 , 6  , 7 ,12,   0 , 5 , 14 , 9]],
    [[10 , 0 ,  9, 14 ,  6,  3,  15,  5 ,  1 ,13,  12,  7 , 11,  4 ,  2 , 8],
     [13 , 7 ,  0 , 9 ,  3,  4 ,  6 ,10  , 2 , 8 ,  5, 14,  12, 11,  15 , 1],
     [13 , 6 ,  4 , 9 ,  8 ,15 ,  3  ,0 , 11 , 1 ,  2 ,12  , 5, 10 , 14 , 7],
      [1 ,10,  13 , 0 ,  6,  9 ,  8 , 7 ,  4 ,15 , 14 , 3 , 11,  5  , 2, 12]],
    [[7, 13 , 14 , 3 ,  0 , 6 ,  9 ,10 ,  1  ,2  , 8 , 5 , 11 ,12 ,  4 ,15],
     [13,  8 , 11 , 5  , 6 ,15,   0,  3,   4 , 7 ,  2, 12 ,  1, 10 , 14,  9],
    [ 10,  6 ,  9 , 0 , 12, 11,   7, 13,  15 , 1 ,  3 ,14 ,  5 , 2,   8,  4],
     [ 3, 15 ,  0 , 6 , 10  ,1 , 13 , 8,   9 , 4 ,  5 ,11,  12,  7 ,  2, 14]],
     [[ 2, 12 ,  4,  1 ,  7, 10  ,11  ,6  , 8,  5 ,  3, 15 , 13 , 0 , 14 , 9],
     [14 ,11 ,  2 ,12 ,  4 , 7 , 13 , 1 ,  5,  0 , 15, 10  , 3 , 9 ,  8,  6],
     [ 4  ,2,   1 ,11 , 10 ,13 ,  7 , 8 , 15 , 9 , 12,  5  , 6 , 3 ,  0, 14],
     [11 , 8 , 12 , 7,   1, 14 ,  2 ,13 ,  6 ,15 ,  0 , 9 , 10 , 4 ,  5,  3]],
    [[12 , 1 , 10 ,15,   9 , 2 ,  6 , 8 ,  0 ,13 ,  3 , 4 , 14 , 7 ,  5, 11],
     [10 ,15 ,  4 , 2 ,  7 ,12 ,  9 , 5 ,  6 , 1 , 13 ,14,   0 ,11 ,  3 , 8],
     [ 9 ,14  ,15 , 5 ,  2,  8,  12 , 3 ,  7,  0 ,  4 ,10,   1, 13 , 11 , 6],
     [ 4 , 3 ,  2 ,12 ,  9 , 5 , 15 ,10,  11 ,14 ,  1,  7 ,  6  ,0 ,  8, 13]],
   [[ 4, 11 ,  2, 14,  15 , 0 ,  8, 13 ,  3 ,12  , 9 , 7,   5 ,10 ,  6,  1],
     [13 , 0 , 11 , 7 ,  4,  9,   1 ,10,  14,  3,   5, 12,   2 ,15,   8 , 6],
     [ 1,  4 , 11 ,13 , 12,  3 ,  7, 14 , 10, 15,   6 , 8 ,  0 , 5 ,  9 , 2],
     [ 6, 11 , 13 , 8 ,  1,  4 , 10,  7,   9,  5 ,  0 ,15,  14 , 2  , 3 ,12]],
    [[13 , 2 ,  8 , 4 ,  6 ,15 , 11 , 1 , 10,  9 ,  3 ,14 ,  5 , 0  ,12 , 7],
      [1 ,15,  13 , 8 , 10 , 3 ,  7,  4,  12,  5 ,  6, 11 ,  0 ,14 ,  9,  2],
     [ 7, 11 ,  4,  1 ,  9 ,12 , 14 , 2,   0,  6  ,10, 13,  15,  3 ,  5,  8],
     [ 2 , 1,  14 , 7 ,  4, 10 ,  8 ,13,  15 ,12,   9 , 0,   3,  5 ,  6, 11]]]                    
# P-substitution box of the result of S-box substitution 
P_box=[16 ,  7 , 20,  21,
   29 , 12,  28 , 17,
    1 , 15 , 23,  26,
    5  ,18 , 31,  10,
    2 ,  8 , 24 , 14,
   32,  27 ,  3 ,  9,
   19 , 13 , 30 ,  6,
   22 , 11 ,  4 , 25] 

def CipherToBin(y):
    cipherbin=''.join(format(int(i,16),'04b') for i in y)
    return cipherbin
def Feistel(R,K): #f(Rn-1,Kn)
    new_R = R_expand(R)
    R_Kxor= xor(new_R,K)
    s_result = S_Substitution(R_Kxor)
    p_result = P_Transposition(s_result)
    return p_result
# Expansion of plaintext R to 48 bits
def R_expand(R):
    new_R=''.join(str(R[i-1]) for i in E_BIT_SELECTION)
    return(new_R) 
# XOR Two List Elements ie R and round subkey
def xor(input1,input2):
    xor_result = []
    for i in range(0,len(input1)):
        xor_result.append(int(input1[i])^int(input2[i]))
    return xor_result    
# Replace XOR results with S-boxes
def S_Substitution(xor_result):
    s_result = []
    for i in range(0,8):
        tmp = xor_result[i*6:i*6+5]
        row = tmp[0]*2+tmp[-1]
        col = tmp[1]*8+tmp[2]*4+tmp[3]*2+tmp[4]
        s_result.append('{:04b}'.format(S[i][row][col]))
    s_result = ''.join(s_result)
    return s_result   
# P-substitution of the result of S-box substitution
def P_Transposition(s_result):
    p_result = []
    for i in P_box:
        p_result.append(int(s_result[i-1]))
    return p_result        
def IP_reverseTransp(K): #final permutation of data
    cipher=''.join(str(K[i-1]) for i in IPinv)
    return cipher            
def SessionKeyTo64bitkey():#generates 64 bit key
    sesskey=RsaDecipher()
    bitkey=''.join(format(ord(i),'08b') for i in sesskey)
    return (bitkey)
def KeyTransposition():# 64 bit key t0 56 bit divided into two halves C and D
    key=SessionKeyTo64bitkey()
    CD=''.join(key[i-1] for i in PC_1)
    C = CD[:28]
    D = CD[28:]
    return (C,D)    
def KeyLeftRotate(C,i): #shift function for rounds of subkey
    C=  C[i:] +   C[:i]
    return(C) 
def KeyCompress(C,D):# Key Compression for each round of subkey
    key= C+D
    newkey=''.join(key[i-1] for i in PC_2)
    return (newkey)
def GenerateKset():   #16 rounds of 48 bit keys
    C,D =KeyTransposition() 
    Kset = []
    for i in LeftRotate:
        C = KeyLeftRotate(C,i)
        D = KeyLeftRotate(D,i)
        Kset.append(KeyCompress(C,D))
    return(Kset)
def CipBinToPlainText(z):
    chunks=[z[i:i+8] for i in range(0,len(z),8)]
    plaintext=''.join(chr(int(j,2)) for j in chunks)
    return plaintext
def RsaDecipher():
    with open('ciphersessionkey.txt','r') as s:
        items=s.readlines()
    cipher = [int(x.strip()) for x in items]
    print(cipher)
    with open ('public.txt','r') as pu:
        n=int(pu.readline())
        e=int(pu.readline())
    publickey=(n,e)
    with open ('private.txt','r') as pu:
        n=int(pu.readline())
        d=int(pu.readline())
    privatekey=(n,d)
    with open('sessionkey.txt','r') as s:
        sessionkey=s.read()
    key=Rsa.DecryptSessionKey(privatekey,cipher)
    return key
def FuncDecryption():
    cipher=[]
    plaintext=[]
    with open('cipher.txt','r') as c:
        size=16
        cip=c.read(size)
        while len(cip)>0:
            cipher.append(cip)
            cip=c.read(size)
    cipherbin=[CipherToBin(y) for y in cipher]
    K=GenerateKset()
    for j in cipherbin:
        cipz=''.join(j[k-1] for k in IP)
        L = cipz[:32]
        R=cipz[32:]
        for i in range(15,0,-1):
                oldR = R
        #F function
                p_result = Feistel(R,K[i])
                R = xor(L,p_result)
                L = oldR
    
        p_result = Feistel(R,K[0])
        L = xor(L,p_result)
        reversedP = IP_reverseTransp(L+R)
        #print(reversedP)
        #print(CipBinToPlainText(reversedP))
        plaintext.append(CipBinToPlainText(reversedP))
    pt=''.join(i for i in plaintext)
    print('decipher:',pt)
    return(pt)
FuncDecryption() 
