import struct
import copy

from Crypto.Cipher import XOR, AES
from Crypto.Hash import SHA512,SHA384

from dh import create_dh_key, calculate_dh_secret

P = list()
Q = list()



class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret-
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))


        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])
        seed = "7f791366fd7bfea4e5b38e2375a8b2338d7758e8ee012468fb255232b64bc927"
        new_seed = HC_256(seed)
        print("new_seed is :{}".format(new_seed))
        new_key = HC_256(shared_hash)
        AES_key = new_key[:16]
        AES_iv = shared_hash[:16]
        self.cipher = AES.new(AES_key,AES.MODE_CBC,AES_iv)

    def send(self, data):
        if self.cipher:
            original_len = len(data)
            remain = 16 - original_len %16
            #Using PKCS7 padding,
            data_after_padding = data + bytes([remain])*remain
            encrypted_data = self.cipher.encrypt(data_after_padding)
            #HMAC with SHA384
            hmac_key = self.cipher.IV
            encrypted_data_Mac = Hmac_SHA384(encrypted_data,hmac_key)
            #Appending MAC to the message
            send_data = encrypted_data+encrypted_data_Mac
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            send_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(send_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(send_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        receive_data = self.conn.recv(pkt_len)
        if self.cipher:
            #Recover the MAC
            encrypted_data_mac = receive_data[-48:]
            #Recover the data
            encrypted_data =  receive_data[:-48]

            hmac_key = self.cipher.IV
            calculate_mac = Hmac_SHA384(encrypted_data,hmac_key)
            
            
            if(calculate_mac != encrypted_data_mac):
                print("Data were modifiered")
                return 

            data = self.cipher.decrypt(encrypted_data)
            #Remove padding 
            data = data[:-data[-1]]
            
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = receive_data

        return data



    def close(self):
        self.conn.close()
    

def Hmac_SHA384(message, key):
        number_of_block = len(key)
        opad = bytes([92])*number_of_block #hex 0x5c
        ipad = bytes([54])*number_of_block #hex 0x36
        opad_key = bytes_XOR(opad,key)
        ipad_key = bytes_XOR(ipad,key)
        internal_hmac = SHA384.new(ipad_key+message).digest()
        return SHA384.new(opad_key+internal_hmac).digest()


def bytes_XOR(byte1,byte2):
        result = bytearray(byte1)
        for i,b in enumerate(byte2):
            result[i] ^=b
        
        return bytes(result)
    
def HC_256(string):
    key = string[:32]
    IV = string[32:]
    W = list()
    K = [key[:4],key[4:8],key[8:12],key[12:16],key[16:20],key[20:24],key[24:28],key[28:32]]
    iv = [IV[:4],IV[4:8],IV[8:12],IV[12:16],IV[16:20],IV[20:24],IV[24:28],IV[28:32]]

    for  i in range(0,2560):
        if (0<=i & i<=7):
            W.append(str(K[i]))
        if (8 <=i & i<= 15):
            W.append(str(iv[i-8]))
        if (16 <=i & i<= 2559):
            output = hex(int(str(f2(W[i-2])),16)+int(str(W[i-7]),16)+int(str(f1(W[i-15])),16)+i)
            W.append(str(output[len(output)-4:]))
        
    global P
    global Q
    for i in range(0,1024):
        P.append(str(W[i+512]))
        Q.append(str(W[i+1536]))
    keystream = []

    for i in range(0,4096):
        j = i%1024
        if (i%2048<1024):
            G1 = g1(P[(j-3)%1024],P[(j-1023)%1024])
            temp = str(hex(int(P[j],16)+int(P[(j-10)%1024],16)+G1))
            P[j] = temp[len(temp)-4:]
            result = str(hex(h1(P[(j-12)%1024]) ^ int(P[j],16))[2:])
            keystream.append(result[len(result)-4:])
        else:
            G1 = int(str(g2(P[(j-3)%1024],P[(j-1023)%1024])),16)
            temp = str(hex(int(Q[j],16)+int(Q[(j-10)%1024],16)+G1))
            Q[j] = temp[len(temp)-4:]
            result = str(hex(h2(Q[(j-12)%1024]) ^ int(Q[j],16))[2:])
            keystream.append(result[len(result)-4:])
        final = ''.join(keystream)
    P.clear()
    Q.clear()
    return final[:64]

def bitrotation(x,bit):
    x1 = int(x,16)
    return int((x1>>bit) ^ (x1<<(32-bit)))

def f1(x):
    return bitrotation(x,7) ^ bitrotation(x,18) ^ (int(str(x),16)>>3)

def f2(x):  
    return bitrotation(x,17) ^ bitrotation(x,19) ^ (int(str(x),16)>>10)

def g1(x,y):
    x1 = int(str(x),16)
    y1 = int(str(y),16)
    Q1 = int(str(Q[(x1^y1)%1024]),16)
    return int(str(bitrotation(x,10)),16) ^ int(str(bitrotation(y,23)),16)+Q1

def g2(x,y):
    x1 = int(str(x),16)
    y1 = int(str(y),16)
    P1 = int(str(P[(x1^y1)%1024]),16)
    return int(str(bitrotation(x,10)),16) ^ int(str(bitrotation(y,23)),16)+P1

def h1(x):
    return int(Q[int(x[:1],16)],16)+int(Q[256+int(x[1:2],16)],16)+int(Q[512+int(x[2:3],16)],16)+int(Q[768+int(x[3:],16)],16)

def h2(x):
    return int(P[int(x[:1],16)],16)+int(P[256+int(x[1:2],16)],16)+int(P[512+int(x[2:3],16)],16)+int(P[768+int(x[3:],16)],16)
