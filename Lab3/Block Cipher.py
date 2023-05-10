# pip install pycryptodome

from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode

pad1 = lambda s: s + (32 - len(s) % 32) * chr(32 -len(s) % 32)
unpad1 = lambda s: s[:-ord(s[len(s) - 1:])]
class Cipher2:
  def __init__(self, key): self.key = md5(key.encode('utf8')). hexdigest()
  def encrypt(self, raw, mode):
    cipher=AES.new(self.key.encode("utf8"), mode)
    return b64encode(cipher. encrypt(pad1 (raw).encode('utf8')))
  def decrypt(self, enc, mode):
    enc = b64decode(enc)
    cipher = AES.new(self.key.encode("utf8"), mode)
    return unpad1(cipher.decrypt (enc)).decode('utf8')
class Cipher1:
  def __init__(self, key): self.key = md5(key.encode('utf8')). digest()
  def encrypt(self, data, mode):
    iv = get_random_bytes (AES. block_size)
    self.cipher=AES.new(self.key, mode, iv)
    return b64encode(iv+ self.cipher. encrypt(pad(data.encode('utf-8'), AES.block_size)))
  def decrypt(self, data, mode):
    raw = b64decode(data)
    self.cipher=AES.new(self.key, mode, raw[:AES.block_size])
    return unpad (self.cipher.decrypt (raw [AES.block_size: ]), AES. block_size)
if __name__=='__main__':
  modes = ['ECB', 'CTR', 'CBC', 'OFB', 'CFB']
  codes = [AES.MODE_ECB, AES.MODE_CTR, AES.MODE_CBC, AES.MODE_OFB, AES.MODE_CFB]
  msg = input('Message: ')
  key = input('Key....:')
  for i in range(2):
    enc=Cipher2(key).encrypt (msg, codes[i])
    dec = Cipher2(key).decrypt (enc, codes[i])
    print(modes[i], 'E:', str(enc) [2:-1], 'D:', dec)
    if modes[i]=="CTR" :
       print("hello")
  for i in range(2, 5):
    enc=Cipher1(key).encrypt (msg, codes[i]).decode('utf-8')
    dec = Cipher1(key).decrypt (enc, codes[i]).decode('utf-8')
    print(modes[i], 'E:', enc, 'D:', dec)