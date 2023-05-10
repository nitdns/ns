def rc4(key, data):
    key = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)


if __name__ == '__main__':
    key = "thisisthekey"
    data = "Prince Kumar 191210038 RC4"
    print(f"Original Message : {data}")
    encrypted = rc4(key, data)
    print(f"Encrypted Message : {encrypted}")

    decrypted = rc4(key, encrypted)
    print(f"Decrypted Message : {decrypted}")

