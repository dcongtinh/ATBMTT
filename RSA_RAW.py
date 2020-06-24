import math


def xgcd(a, b):  # Extended Euclidean Algorithm ~ a^-1 % b
    tmp = b
    x0, x1 = 1, 0
    while b > 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        if x0 < 0:
            x0 += tmp
    return x0


p, q = 3, 5
n = p*q
phin = (p-1)*(q-1)
e = 11
d = xgcd(e, phin)

print("e=%d" % e)
print("n=%d" % n)
print("d=%d" % d)
print("Ku={%d, %d}" % (e, n))
print("Kr={%d, %d}" % (d, n))

plaintext = "dcongtinh"
print("\nplaintext=%s" % plaintext)


def str2char(s):
    char_arr = ''
    for c in s:
        char_arr += str(ord(c)) + ' '
    return char_arr.strip()


def char2str(char_arr, d=10):
    char_arr = char_arr.split()
    s = ''
    for hex_el in char_arr:
        # bytes_object = bytes.fromhex(hex_el)
        # ascii_string = bytes_object.decode("hex")
        # print(ascii_string)
        s += chr(int(hex_el, d))
    return s


def encrypt(plaintext):
    s = str2char(plaintext)
    ciphertext = ''
    print("\nplaintext  = %s" % s)
    for c in s:
        if c != ' ':
            ciphertext += hex(int(c)**e % n)[2:]
        else:
            ciphertext += ' '
    print("\nciphertext = %s" % ciphertext)
    print(char2str(ciphertext, 16))
    return ciphertext


def decrypt(ciphertext):
    plaintext = ''
    for c in ciphertext:
        if c == ' ':
            plaintext += ' '
        else:
            plaintext += hex(int(c, 16)**d % n)[2:]

    print("\nplaintext  = %s" % plaintext)
    print(char2str(plaintext))
    return plaintext


ciphered = encrypt(plaintext)
decrypt(ciphered)
