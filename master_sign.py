import os
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA

def sign_file(f):
    #sign files using master's private key

    #load private key
    key = RSA.importKey(open('privkey.pem').read())
    hashed = SHA384.new(f)
    signer = PKCS1_v1_5.new(key)
    #sign the file
    signature = signer.sign(hashed)

    return signature + f
    


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
