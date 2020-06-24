# Mat ma Affine
# -*- coding: utf-8 -*-
from tkinter import *
from pydes import des
window = Tk()
window.title("CHƯƠNG TRÌNH DEMO")
lb0 = Label(window, text=" ", font=("Arial Bold", 10))
lb0.grid(column=0, row=0)
lbl = Label(window, text="GIẢI THUẬT DES (pydes)", font=("Arial Bold", 20))
lbl.grid(column=0, row=1, columnspan=6, pady=16)
# lb2 = Label(window, text="GIẢI THUẬT DES (pydes)", font=("Arial Bold", 15))
# lb2.grid(column=0, row=2)
plainlb3 = Label(window, text="PLAIN TEXT", font=("Arial", 14))
plainlb3.grid(column=0, row=3, sticky="E")
plaintxt = Entry(window, width=20)
plaintxt.grid(column=1, row=3)
KEYlb4 = Label(window, text="KEY", font=("Arial", 14))
KEYlb4.grid(column=2, row=3, sticky="E")
SecretKey = Entry(window, width=20)
SecretKey.grid(column=3, row=3)
lb5 = Label(window, text="CIPHER TEXT", font=("Arial", 14))
lb5.grid(column=0, row=4, sticky="E")
ciphertxt3 = Entry(window, width=20)
ciphertxt3.grid(column=1, row=4)
denctxt3 = Entry(window, width=20)
denctxt3.grid(column=3, row=4)

lbSTT = Label(window, text="", font=("Arial", 14), fg="red")
lbSTT.grid(column=1, row=5, columnspan=4, sticky="W")

d = des()
ciphered = ""


def matma():
    print('Mật Mã clicked  !!!')
    lbSTT['text'] = ''
    if len(plaintxt.get()) == 0:
        lbSTT['text'] = '* Vui lòng nhập PLAINTEXT'
        return
    if len(SecretKey.get()) == 0:
        lbSTT['text'] = '* Vui lòng nhập KEY'
        return
    if len(SecretKey.get()) % 8 != 0 and len(plaintxt.get()) % 8 != 0:
        lbSTT['text'] = '* Độ dài PLAINTEXT và KEY là bội của 8 !!!'
        return
    if len(plaintxt.get()) % 8 != 0:
        lbSTT['text'] = '* Độ dài PLAINTEXT là bội của 8 !!!'
        return
    if len(SecretKey.get()) % 8 != 0:
        lbSTT['text'] = '* Độ dài KEY là bội của 8 !!!'
        return
    global ciphered
    ciphered = d.encrypt(SecretKey.get(), plaintxt.get())
    print('KEY =', SecretKey.get(), 'PLAINTEXT =', plaintxt.get())
    print("Ciphered: %r" % ciphered)
    ciphertxt3.delete(0, END)
    ciphertxt3.insert(INSERT, ciphered)


def giaimat():
    print('Giải Mật clicked  !!!')
    deciphered = d.decrypt(SecretKey.get(), ciphered)
    print('KEY =', SecretKey.get(), 'DECRYPTEXT =', deciphered)
    print("Deciphered: %s" % deciphered)
    denctxt3.delete(0, END)
    denctxt3.insert(INSERT, deciphered)


EncrypBtn = Button(window, text="Mật Mã", command=matma)
EncrypBtn.grid(column=5, row=3)
DecryptBtn = Button(window, text="Giải Mật", command=giaimat)
DecryptBtn.grid(column=2, row=4)
window.geometry('600x200')
window.mainloop()
