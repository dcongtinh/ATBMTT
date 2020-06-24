from Crypto.Cipher import DES3
from Crypto import Random

key = 'Sixteen byte key'
iv = Random.new().read(DES3.block_size)
cipher = DES3.new(key, DES3.MODE_CBC, iv)
plaintext = b'sona si latine loqueris '
ciphered = cipher.encrypt(plaintext)
print(ciphered)
decipher = DES3.new(key, DES3.MODE_CBC, iv)
deciphered = decipher.decrypt(ciphered)
print(deciphered)
