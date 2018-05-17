from Crypto.PublicKey import RSA

#generate new RSA key pairs
key = RSA.generate(2048)
#store private key
f = open('privkey.pem','w')
f.write(key.exportKey('PEM').decode('utf-8'))
f.close()
#store public key
f = open('pubkey.pem','w')
f.write(key.publickey().exportKey('PEM').decode('utf-8'))
f.close()