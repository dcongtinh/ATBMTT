from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
f = open('private.pem', 'wb')
f.write(key.exportKey('PEM'))
f.close()

f = open('public.pem', 'wb')
f.write(key.publickey().exportKey('PEM'))
f.close()


def genkeypair():
    key = RSA.generate(2048)
    pubkey = key.publickey().exportKey('PEM')
    privkey = key.exportKey('PEM')
    return (pubkey, privkey)


message = b'You can attack now!'
key = RSA.importKey(open('public.pem').read())
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
print('ciphertext =', ciphertext)

key = RSA.importKey(open('private.pem').read())
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)
print('message =', message.decode('ascii'))
