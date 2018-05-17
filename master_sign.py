import os
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    key = RSA.importKey(open('privkey.pem').read())
    hashed = SHA384.new(f)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hashed)

    return signature + f
    #bytes("Caesar\n", "ascii") + f


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
