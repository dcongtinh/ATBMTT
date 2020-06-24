# RSA
# -*- coding: utf-8 -*-
from tkinter import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
window = Tk()
window.title("CHƯƠNG TRÌNH DEMO")
lb0 = Label(window, text=" ", font=("Arial Bold", 10))
lb0.grid(column=0, row=0)
lbl = Label(window, text="GIẢI THUẬT RSA", font=("Arial Bold", 20))
lbl.grid(column=0, row=1, columnspan=6, pady=16)
plainlb3 = Label(window, text="PLAIN TEXT", font=("Arial", 14))
plainlb3.grid(column=0, row=3, sticky="E")
lb5 = Label(window, text="CIPHER TEXT", font=("Arial", 14))
lb5.grid(column=0, row=4, sticky="E")
ciphertxt3 = Entry(window, width=20)
ciphertxt3.grid(column=1, row=4)
denctxt3 = Entry(window, width=20)
denctxt3.grid(column=3, row=4)

lbSTT = Label(window, text="", font=("Arial", 14), fg="red")
lbSTT.grid(column=1, row=5, columnspan=4, sticky="W")

key = RSA.generate(2048)  # Sinh khoá
ciphered = ''
# Lưu khoá cá nhân (để mật mã)
f = open('private.pem', 'wb')
f.write(key.exportKey('PEM'))
f.close()

# Lưu khoá công khai (để mật mã)
f = open('public.pem', 'wb')
f.write(key.publickey().exportKey('PEM'))
f.close()


def onkeypress(event):
    ciphertxt3.delete(0, END)


def genkeypair():
    key = RSA.generate(2048)
    pubkey = key.publickey().exportKey('PEM')
    privkey = key.exportKey('PEM')
    return (pubkey, privkey)


def matma():
    print('Mật Mã clicked  !!!')
    global ciphered
    pubkey = RSA.importKey(open('public.pem').read())
    cipher = PKCS1_OAEP.new(pubkey)
    ciphered = cipher.encrypt(plaintxt.get().encode('utf-8'))
    print('PLAINTEXT =', plaintxt.get())
    print('ciphered =', ciphered)

    ciphertxt3.delete(0, END)
    ciphertxt3.insert(INSERT, 'Plaintext được mật mã!')
    # ciphertxt3.insert(INSERT, ciphered.decode('utf-8', errors="ignore"))


def giaimat():
    print('Giải Mật clicked  !!!')
    privkey = RSA.importKey(open('private.pem').read())
    decipher = PKCS1_OAEP.new(privkey)
    deciphered = decipher.decrypt(ciphered)
    print("Deciphered: %s" % deciphered)
    denctxt3.delete(0, END)
    denctxt3.insert(INSERT, deciphered.decode('utf-8'))


plaintxt = Entry(window, width=20)
plaintxt.bind('<Key>', onkeypress)
plaintxt.grid(column=1, row=3)
EncrypBtn = Button(window, text="Mật Mã", command=matma)
EncrypBtn.grid(column=2, row=3)
DecryptBtn = Button(window, text="Giải Mật", command=giaimat)
DecryptBtn.grid(column=2, row=4)
window.geometry('600x200')
window.mainloop()
