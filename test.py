# -*- coding: utf-8 -*-
from tkinter import *

window = Tk()
window.title('THIS IS A TITLE')
lbSpace = Label(window, text=" ", font=('Arial', 10))
lbSpace.grid(row=0, column=0)
lb0 = Label(window, text="Chuong trinh demo", font=('Fira Code', 20))
lb0.grid(row=1, column=1, columnspan=4)
lb_plaintext = Label(window, text="Plaintext")
lb_plaintext.grid(row=2, column=0)
plaintext = Entry(window)
plaintext.grid(row=2, column=1)


def xgcd(a, b):
    tmp = b
    x0, x1 = 1, 0
    while b > 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q*x1
        if x0 < 0:
            x0 += tmp
    return x0


def num2char(x):
    return chr(x + 65)


def char2num(c):
    return ord(c) - 65


def encrypt(s, a, b, m):
    t = ""
    for c in s:
        x = (a*char2num(c) + b) % m
        t += num2char(x)
    return t


def decrypt(s, a, b, m):
    t = ""
    a1 = xgcd(a, m)
    for c in s:
        x = (a1 * (char2num(c)-b)) % m
        t += num2char(x)
    return t


def GET():
    print(plaintext.get())
    plaintext.delete(0, END)


btn = Button(window, text='GET', command=GET)
btn.grid(row=2, column=2)
message = 'TINHDAO'
a, b, m = 13, 11, 27

enciphered = encrypt(message, a, b, m)
print(enciphered)
deciphered = decrypt(enciphered, a, b, m)
print(deciphered)

window.geometry('600x300')
window.mainloop()

# from Crypto.PublicKey import RSA
# from Crypto.Cipher import DES3, AES, PKCS1_OAEP
# key = RSA.generate(2048)
# print(key.exportKey('PEM'))
# print(key.publickey().exportKey('PEM'))

# cipher = PKCS1_OAEP.new(key.exportKey('PEM'))
# ciphered = cipher.encrypt(message.encode('utf-8'))
