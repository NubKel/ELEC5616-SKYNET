import struct

from Crypto.Cipher import XOR, AES
from Crypto.Hash import SHA512,SHA384

from dh import create_dh_key, calculate_dh_secret



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
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))


        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])
        AES_key = shared_hash[:32]
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