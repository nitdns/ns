import random
import string
def feistel_encr(self, message):
    ciphertext=""
    n=self.BLOCKSIZE
    message = [message[i: i + n] for i in range(0, len(message), n)]
    lengthOfLastBlock = len(message[len(message)-1])
    if ( lengthOfLastBlock < self.BLOCKSIZE):
        for i in range(lengthOfLastBlock, self.BLOCKSIZE):
            message[len(message)-1] += " "
    for block in message:
        L = [""] * (self.ROUNDS + 1)
        R = [""] * (self.ROUNDS + 1)
        L[0] = block[0:8]
        R[0] = block[8:16]
        for i in range(1, self.ROUNDS+1):
            L[i] = R[i - 1]
            R[i] = xor(L[i-1], f(R[i-1], self.KEYS[i-1]))
        ciphertext += (L[self.ROUNDS] + R[self.ROUNDS])
    return ciphertext

def feistel_decr(self, ciphertext):
    message = ""
    n = self.BLOCKSIZE
    ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]
    lengthOfLastBlock = len(ciphertext[len(ciphertext)-1])
    if ( lengthOfLastBlock < self.BLOCKSIZE):
        for i in range(lengthOfLastBlock, self.BLOCKSIZE):
            ciphertext[len(ciphertext)-1] += " "
    for block in ciphertext:
        L = [""] * (self.ROUNDS + 1)
        R = [""] * (self.ROUNDS + 1)
        L[self.ROUNDS] = block[0:8]
        R[self.ROUNDS] = block[8:16]
        for i in range(4, 0, -1):
            R[i-1] = L[i]
            L[i-1] = xor(R[i], f(L[i], self.KEYS[i-1]))
        message += (L[0] + R[0])
    return message

def gen_keys(self):
    for i in range(0, 4):
        length = 8 # 8 bytes - 64 bit key
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        self.KEYS.append(result_str)
def f(r, k_i):
    x = stobin(str(r))
    k = stobin(k_i)
    x = bintoint(x)
    k = bintoint(k)
    res = (x%pow(2, 64) * k%pow(2, 64))%pow(2, 64)
    res = itobin(res)
    return bintostr(res)

def xor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
def stobin(s):
    return ''.join('{:08b}'.format(ord(c)) for c in s)
def bintoint(s):
    return int(s, 2)
def itobin(i):
    return bin(i)
def bintostr(b):
    n = int(b, 2)
    return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))

