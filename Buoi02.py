# Mat ma Khoa doi xung (SKC)
# -*- coding: utf-8 -*-
import sys
from tkinter import *
from Crypto.Cipher import AES, DES3
from Crypto import Random
from pydes import des

window = Tk()
window.title("CHƯƠNG TRÌNH DEMO")
lb0 = Label(window, text=" ", font=("Arial Bold", 10))
lb0.grid(column=0, row=0)
lbl = Label(window, text="MẬT MÃ KHOÁ ĐỐI XỨNG (SKC)", font=("Arial Bold", 20))
lbl.grid(column=0, row=1, columnspan=6, pady=16)
lbAlgo = Label(window, text="ALGO", font=("Arial", 14),)
lbAlgo.grid(column=0, row=2, sticky="E")
lbMode = Label(window, text="MODE", font=("Arial", 14),)
lbMode.grid(column=2, row=2, sticky="E")

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

d = des()
algo = AES
mode = algo.MODE_ECB
ciphered = ""
iv = Random.new().read(algo.block_size)
description = {
    "AES (pycrypto)": '* Độ dài KEY 16 (AES-128), 24 (AES-192), 32 (AES-256)\n* Độ dài PLAINTEXT là bội của 16',
    'DES (pycrypto)': '* Độ dài KEY 16 hoặc 24\n* Độ dài PLAINTEXT là bội của 8',
    "DES (pydes)": '* Độ dài KEY >= 8\n* Độ dài PLAINTEXT là bội của 8'
}


def bin2txt(bin_val):
    return bin_val.decode('utf-8')


def change_algo_option(option):
    global algo, iv
    algo = AES if option == 'AES (pycrypto)' else DES3
    iv = Random.new().read(algo.block_size)
    lbDes['text'] = description[option]
    mode_options['state'] = 'disabled' if option == 'DES (pydes)' else 'normal'
    ciphertxt3.delete(0, END)
    denctxt3.delete(0, END)


def change_mode_option(option):
    global mode
    mode = algo.MODE_CBC if option == 'CBC' else algo.MODE_ECB
    ciphertxt3.delete(0, END)
    denctxt3.delete(0, END)


def matma():
    print('Mật Mã clicked  !!!')
    msg = plaintxt.get()
    key = SecretKey.get()
    ok = True
    global ciphered
    if "pycrypto" in var_algo.get():
        obj = algo.new(key, mode, iv)  # Cipher-Block Chaining
        ciphered = obj.encrypt(msg)
    else:
        ciphered = d.encrypt(key, msg)

    print('KEY =', key, 'PLAINTEXT =', msg)
    print("Ciphered: %r" % ciphered)
    ciphertxt3.delete(0, END)
    ciphertxt3.insert(INSERT, ciphered)


def giaimat():
    print('Giải Mật clicked  !!!')
    key = SecretKey.get()
    if "pycrypto" in var_algo.get():
        obj = algo.new(key, mode, iv)
        deciphered = obj.decrypt(ciphered)
        deciphered = bin2txt(deciphered)
    else:
        deciphered = d.decrypt(SecretKey.get(), ciphered)

    print('KEY =', key, 'DECRYPTEXT =', deciphered)
    denctxt3.delete(0, END)
    denctxt3.insert(INSERT, deciphered)


lbDes = Label(window, text=description["AES (pycrypto)"], font=(
    "Arial", 14), fg="red")
lbDes.grid(column=1, row=5, columnspan=4)

EncrypBtn = Button(window, text="Mật Mã", command=matma)
EncrypBtn.grid(column=5, row=3)
DecryptBtn = Button(window, text="Giải Mật", command=giaimat)
DecryptBtn.grid(column=2, row=4)

var_algo = StringVar(window)
var_algo.set("AES (pycrypto)")  # default value
algo_options = ["AES (pycrypto)", "DES (pycrypto)", "DES (pydes)"]
algo_options = OptionMenu(
    window, var_algo, *(algo_options), command=change_algo_option)
algo_options.grid(column=1, row=2)

var_mode = StringVar(window)
var_mode.set("ECB")  # default value
mode_options = ["ECB", "CBC"]
mode_options = OptionMenu(window, var_mode, *(mode_options),
                          command=change_mode_option)
mode_options.grid(column=3, row=2)

dim = '600x220' if sys.platform == 'darwin' else '700x240'
window.geometry(dim)
window.mainloop()
