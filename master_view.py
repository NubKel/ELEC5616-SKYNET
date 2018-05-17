import os
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def decrypt_valuables(f):
    #decrypt files using master's private key

    #load private key
    key = RSA.importKey(open('privkey.pem').read())
    cipher = PKCS1_v1_5.new(key)
    #decrypt the ciphertext
    plaintext = cipher.decrypt(f,1)
    plaintext = plaintext.decode('utf-8')
    print(plaintext)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
