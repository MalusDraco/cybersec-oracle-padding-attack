
#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()

# Automatically update CC1 ByteArray
def updateCC1(k, bytearr, D2):
    if k <= 1:
        return

    for i in range(1,k):
        bytearr[16-i] = D2[16-i] ^ k

# Decodes block 1 and 2
def decodeBlock(IV, C1, C2):
    D2 = bytearray(16)
    CC1 = bytearray(16)

    for K in range(1,16):
        updateCC1(K, CC1, D2)
        for i in range(256):
              CC1[16 - K] = i
              status = oracle.decrypt(IV + CC1 + C2)
              if status == "Valid":
                  #print("Valid: i = 0x{:02x}".format(i))
                  #print("CC1: " + CC1.hex())
                  D2[16 - K] = i ^ K

    P2 = xor(C1, D2)
    print("P2:  " + P2.hex())
    # P2 = bytearray.fromhex(P2.hex()).decode()
    return str(P2)

if __name__ == "__main__":
    oracle = PaddingOracle('10.9.0.80', 6000)

    iv_and_ctext = bytearray(oracle.ctext)
    blocklist = [ iv_and_ctext[i:i+16] for i in range(0, len(iv_and_ctext), 16) ]
    num_runs = len(blocklist) - 2

    currBlocks = []
    out = ""
    init_IV = bytearray(16)
    # Add first two blocks
    currBlocks.append(blocklist.pop(0))
    currBlocks.append(blocklist.pop(0))
    out = ""
    out += decodeBlock(init_IV, currBlocks[0], currBlocks[1])  # Decode first block w/ blank IV
    for i in range(num_runs):
        currBlocks.append(blocklist.pop(0))
        out += decodeBlock(currBlocks[0], currBlocks[1], currBlocks[2])
        currBlocks.pop(0)
        # print(f"current out: {out}")
    #out += decodeBlock(blocklist[0], blocklist[1], blocklist[2])
    #out += decodeBlock(blocklist[1], blocklist[2], blocklist[3])
    print(out)