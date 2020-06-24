# RSA
# -*- coding: utf-8 -*-
from tkinter import *
window = Tk()
window.title("CHƯƠNG TRÌNH DEMO")
lb0 = Label(window, text=" ", font=("Arial Bold", 10))
lb0.grid(column=0, row=0)
lbl = Label(window, text="GIẢI THUẬT RSA", font=("Arial Bold", 20))
lbl.grid(column=0, row=1, columnspan=6, pady=16)
plainlb3 = Label(window, text="PLAIN TEXT", font=("Arial", 14))
plainlb3.grid(column=0, row=3, sticky="E")
plaintxt = Entry(window, width=20)
plaintxt.grid(column=1, row=3)
lb5 = Label(window, text="CIPHER TEXT", font=("Arial", 14))
lb5.grid(column=0, row=4, sticky="E")
ciphertxt3 = Entry(window, width=20)
ciphertxt3.grid(column=1, row=4)
denctxt3 = Entry(window, width=20)
denctxt3.grid(column=3, row=4)

lbSTT = Label(window, text="", font=("Arial", 14), fg="red")
lbSTT.grid(column=1, row=5, columnspan=4, sticky="W")


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
ciphered = ""


def str2char(s):
    char_arr = ''
    for c in s:
        char_arr += str(ord(c)) + ' '
    return char_arr.strip()


def char2str(char_arr, d=10):
    char_arr = char_arr.split()
    s = ''
    for hex_el in char_arr:
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
    print(char2str(ciphertext, n+1))
    return ciphertext


def decrypt(ciphertext):
    plaintext = ''
    for c in ciphertext:
        if c == ' ':
            plaintext += ' '
        else:
            plaintext += hex(int(c, n+1)**d % n)[2:]

    print("\nplaintext  = %s" % plaintext)
    print(char2str(plaintext))
    return plaintext


def matma():
    print('Mật Mã clicked  !!!')
    global ciphered
    ciphered = encrypt(plaintxt.get())
    print('PLAINTEXT =', plaintxt.get())
    print("Ciphered: %r" % ciphered)
    ciphertxt3.delete(0, END)
    ciphertxt3.insert(INSERT, char2str(ciphered, n+1))


def giaimat():
    print('Giải Mật clicked  !!!')
    deciphered = decrypt(ciphered)
    print('DECRYPTEXT =', deciphered)
    print("Deciphered: %s" % deciphered)
    denctxt3.delete(0, END)
    denctxt3.insert(INSERT, char2str(deciphered))


EncrypBtn = Button(window, text="Mật Mã", command=matma)
EncrypBtn.grid(column=2, row=3)
DecryptBtn = Button(window, text="Giải Mật", command=giaimat)
DecryptBtn.grid(column=2, row=4)
window.geometry('600x200')
window.mainloop()
