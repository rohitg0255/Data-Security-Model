import RSAkeygeneration
import DesE
import DesD
def main():
    print("message:{}".format(DesE.text))
    print(f'cipher={DesE.FuncEncryption()}')
    decipher=DesD.FuncDecryption()
    print('decipher plaintext:',decipher)
    return
if __name__==('__main__'):
        main()