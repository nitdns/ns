import _csb451_crypto
class FeistelCipher:
    BLOCKSIZE = 16 # 16 bytes - 128 bits per block
    ROUNDS = 4
    KEYS = []
    def __init__(self):
        pass
    def feistel_encr(self, message):
        return _csb451_crypto.feistel_encr(self, message)
    def feistel_decr(self, ciphertext):
        return _csb451_crypto.feistel_decr(self, ciphertext)
    def gen_keys(self):
        _csb451_crypto.gen_keys(self)

x = FeistelCipher()
x.gen_keys()
encrypted_text = x.feistel_encr("Prince Kumar 38 Lab-4 Feistel cipher")
print("Encrypted Text: ", encrypted_text)
decrypted_text = x.feistel_decr(encrypted_text)
print("Decrypted Text: ", decrypted_text)
