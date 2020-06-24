plaintext = "TINH"
p = 3
q = 11


def num2char(x):
    return chr(x + 65)


def char2num(c):
    return ord(c) - 65


def xgcd(a, b):
    tmp = b
    x0, x1 = 1, 0
    while b > 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q*x1
        if x0 < 0:
            x0 += tmp
    return x0


def decryptAF(c, a, b, m):
    return (a * char2num(c) + b) % m


def encryptAF(c, a, b, m):
    a1 = xgcd(a, 26)
    return (a1*(char2num(c) - b)) % m


def matma():
    ciphertext = ""
    for c in plaintext:
        ciphertext += num2char(decryptAF(c, p, q, 26))
    return ciphertext


def giaimat():
    plaintext = ""
    ciphertext = mahoa()
    for c in ciphertext:
        plaintext += num2char(encryptAF(c, p, q, 26))
    return plaintext


print('plaintext   =', plaintext)
print('cirphertext =', matma())
print('plaintext   =', giaimat())
