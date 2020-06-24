# Mat ma Affine
# -*- coding: utf-8 -*-
from tkinter import *
window = Tk()
window.title("Welcome to Demo An Toan Bao Mat Thong Tin")
lb0 = Label(window, text=" ", font=("Arial Bold", 10))
lb0.grid(column=0, row=0)
lbl = Label(window, text="CHƯƠNG TRÌNH DEMO", font=("Arial Bold", 20))
lbl.grid(column=1, row=1, columnspan=4)
lb2 = Label(window, text="MẬT MÃ AFFINE", font=("Arial Bold", 15))
lb2.grid(column=0, row=2)
plainlb3 = Label(window, text="PLANT TEXT", font=("Arial", 14))
plainlb3.grid(column=0, row=3)
plaintxt = Entry(window, width=20)
plaintxt.grid(column=1, row=3)
KEYlb4 = Label(window, text="KEY PAIR", font=("Arial", 14))
KEYlb4.grid(column=2, row=3)
KEYA = Entry(window, width=4)
KEYA.grid(column=3, row=3)
KEYB = Entry(window, width=4)
KEYB.grid(column=4, row=3)
lb5 = Label(window, text="CIPHER TEXT", font=("Arial", 14))
lb5.grid(column=0, row=4)
ciphertxt3 = Entry(window, width=20)
ciphertxt3.grid(column=1, row=4)
denctxt3 = Entry(window, width=20)
denctxt3.grid(column=3, row=4)


def Char2Num(c):
    return ord(c) - 65


def Num2Char(n):
    return chr(n + 65)


def xgcd(a, b):  # Extended Euclidean Algorithm
    tmp = b
    x0, x1 = 1, 0
    while b > 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        if x0 < 0:
            x0 += tmp
    return x0

# def xgcd(a, m): # a^-1 % m
#     if isPrime(m):
#         return a**(m-2) % m
#     else: # Any value of m
#         return a**(phi(n)-1) % m


def encryptAF(txt, a, b, m):
    r = ""
    for c in txt:
        e = (a * Char2Num(c) + b) % m
        r += Num2Char(e)
    return r


def decryptAF(txt, a, b, m):
    r = ""
    a1 = xgcd(a, m)
    for c in txt:
        e = (a1 * (Char2Num(c) - b)) % m
        r += Num2Char(e)
    return r


def matma():
    a, b, m = int(KEYA.get()), int(KEYB.get()), 26
    cirphertext = encryptAF(plaintxt.get(), a, b, m)
    ciphertxt3.delete(0, END)
    ciphertxt3.insert(INSERT, cirphertext)


def giaimat():
    a, b, m = int(KEYA.get()), int(KEYB.get()), 26
    decryptext = decryptAF(ciphertxt3.get(), a, b, m)
    denctxt3.delete(0, END)
    denctxt3.insert(INSERT, decryptext)


AFbtn = Button(window, text="Mã Hóa", command=matma)
AFbtn.grid(column=5, row=3)
DEAFbtn = Button(window, text="Giải Mã ", command=giaimat)
DEAFbtn.grid(column=2, row=4)
window.geometry('700x200')
window.mainloop()
