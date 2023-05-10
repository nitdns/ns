import string
import random
import sys
abc = string.ascii_uppercase
one_time_pad = list(abc)

def encrypt(msg, key):
  key = key.replace(" ",'')
  msg = msg.replace(" ",'')
  ciphertext = ''
  for idx, char in enumerate(msg):
    charIdx = abc.index(char)
    keyIdx = one_time_pad.index(key[idx])
    cipher = (keyIdx + charIdx) % len(one_time_pad)
    ciphertext += abc[cipher]
  print("Encrypted Message: ",ciphertext)


def decrypt(ciphertext, key):
  if ciphertext == '' or key == '':
    return ''
  charIdx = abc.index(ciphertext[0])
  keyIdx = one_time_pad.index(key[0])
  cipher = (charIdx - keyIdx) % len(one_time_pad)
  char = abc[cipher]
  print("Decrypted Message: ", char + decrypt(ciphertext[1:], key[1:]))

if __name__ == '__main__':
  opt = input("Enter 1 to Encrypt or 2 to Decrypt: ")
  key = input("Key: ")
  msg = input("Message: ")
  if opt=='1':
    print(encrypt(msg, key))
  elif opt=='2':
    print(decrypt(msg, key))

# Key : X V H E U W N O P G D Z X V H E U W N O P G D Z X V
# Plaintext : WE LIVE IN A WORLD FULL OF BEAUTY