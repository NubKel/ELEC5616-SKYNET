from Crypto.PublicKey import RSA

key = RSA.generate(2048)
f = open('privkey.pem','w')
f.write(key.exportKey('PEM').decode('utf-8'))
f.close()
f = open('pubkey.pem','w')
f.write(key.publickey().exportKey('PEM').decode('utf-8'))
f.close()