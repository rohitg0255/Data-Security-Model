
def EncryptSessionKey(publickey, sessionkey):
    n,key = publickey    #Unpack the key into it's components
    cipher = [pow(ord(char),key,n) for char in sessionkey]
    print(cipher)
    #Convert each letter in the plaintext to numbers based on char using a^b(mod m)
    return cipher           #Return the array of bytes
def DecryptSessionKey(privatekey, cipher):
    #Unpack the key into its components
    n,key = privatekey
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in cipher]
    #Return the array of bytes as a string
    print(plain)
    return ''.join(plain)
