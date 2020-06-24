# -*- coding: utf-8 -*-
"""
Created on Thu Jun  4 11:22:42 2020

@author: lenovo
"""

from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from Crypto.Hash import SHA
import re

#---------------------------------Thuật toán----------------------------------#


class RSA:
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

    # Mã hóa từng ký tự kiểu int
    def encrypt_i(self, plain):
        cipher = pow(plain, self.e) % self.n
        return cipher

    # Giải mã từng ký tự kiểu int
    def decrypt_i(self, cipher):
        plain = pow(cipher, self.d) % self.n
        return plain

    # Mã hóa chuỗi ký tự kiểu str
    def encrypt(self, plain_txt):
        # List các str co so trong doan text
        find = re.findall(r'[0-9]+', plain_txt)
        find_txt = ''.join(find)  # Noi cac phan tu trong list thanh chuoi
        # Neu plain_txt chua ca chu va so hoac bat dau bang ky tu 0
        if plain_txt[0] == "0" or find == "" or len(find) != 1:
            plain = ""
            for i in plain_txt:
                if ord(i) < 10:
                    str_ord = "00" + str(ord(i))
                if ord(i) >= 10 and ord(i) < 100:
                    str_ord = "0" + str(ord(i))
                if ord(i) >= 100:
                    str_ord = str(ord(i))
                plain = plain.__add__(str_ord)

            cipher = "0x"
            for i in plain:
                en_i = self.encrypt_i(int(i))
                hex_i = hex(en_i)
                for j in range(2, len(hex_i)):
                    cipher = cipher.__add__(hex_i[j])
            return cipher
        # Neu plain_txt chi chua so va khong bat dau bang ky tu 0
        else:
            return self.encrypt_i(int(find_txt))

    # Giải mã chuỗi ký tự kiểu str
    def decrypt(self, cipher_txt):
        find = re.findall(r'[0-9]+', cipher_txt)
        find_txt = ''.join(find)
        if cipher_txt[0] == "0" or find == "" or len(find) != 1:
            result = ""
            for i in range(2, len(cipher_txt)):
                dec_i = int(cipher_txt[i], 16)
                de_i = self.decrypt_i(dec_i)
                result = result.__add__(str(de_i))

            def group_adjacent(a, k): return list(zip(*([iter(a)] * k)))
            text_i = group_adjacent(result, 3)
            res = ""
            for i in text_i:
                txt_i = ''.join(i)
                res += chr(int(txt_i.lstrip("0")))
            return res
        else:
            return self.decrypt_i(int(find_txt))


#---------------------------------Giao diện-----------------------------------#
window = Tk()
window.title("Sign the document")

# main_container = Frame(window, background="bisque")
main_container = Frame(window)
main_container.pack(side="top", fill="both", expand=True)
label_len = 16
#------Ký văn bản-------#
n = 15
e = 11
d = 3
key = RSA(n, e, d)

stepOne = LabelFrame(main_container, text=" Enter File Details: ")
stepOne.grid(row=0, columnspan=8, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)


inFileLbl = Label(stepOne, text="Select The File (Path):", width=label_len)
inFileLbl.grid(row=0, column=0, sticky='E', padx=5, pady=2)

inFileTxt = Entry(stepOne, width=40)
inFileTxt.grid(row=0, column=1, columnspan=5, sticky="WE", padx=5, pady=3)


def clicked_inFile():
    inFile = filedialog.askopenfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    inFileTxt.delete(0, END)
    inFileTxt.insert(INSERT, inFile)


inFileBtn = Button(stepOne, text="Browse ...", command=clicked_inFile)
inFileBtn.grid(row=0, column=6, sticky='E', padx=5, pady=2)

outFileLbl = Label(stepOne, text="Save File to (Path):", width=label_len)
outFileLbl.grid(row=1, column=0, sticky='E', padx=5, pady=2)

outFileTxt = Entry(stepOne, width=40)
outFileTxt.grid(row=1, column=1, columnspan=5, sticky="WE", padx=5, pady=2)


def clicked_outFile():
    outFile = filedialog.asksaveasfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    outFileTxt.delete(0, END)
    outFileTxt.insert(INSERT, outFile)


outFileBtn = Button(stepOne, text="Browse ...", command=clicked_outFile)
outFileBtn.grid(row=1, column=6, sticky='E', padx=5, pady=2)


def clicked_OK():
    f = open(inFileTxt.get(), 'r')
    document = f.read()
    f.close()

    doc_txt = bytes(document, 'utf-8')
    h = SHA.new()
    h.update(doc_txt)
    doc_hash = h.hexdigest()

    sign = key.encrypt(doc_hash)

    f = open(outFileTxt.get(), 'a+')
    f.write(document + "\n")
    f.write(sign)
    f.close()

    messagebox.showinfo('Message', '\nFinished!')


okBtn = Button(stepOne, text="SIGN", command=clicked_OK)
okBtn.grid(row=3, column=0, columnspan=8, sticky='WE', padx=5, pady=2)

#----------Xác thực văn bản đã được ký----------#
stepTwo = LabelFrame(
    main_container, text="Validate text (hex):")
stepTwo.grid(row=2, columnspan=8, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

sigdocLbl = Label(stepTwo, text="The Signed File (Path):", width=label_len)
sigdocLbl.grid(row=0, column=0, sticky='E', padx=5, pady=2)

sigdocTxt = Entry(stepTwo, width=40)
sigdocTxt.grid(row=0, column=1, columnspan=5, sticky='WE', padx=5, pady=2)


def clicked_sigdoc():
    sigdoc = filedialog.askopenfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    sigdocTxt.delete(0, END)
    sigdocTxt.insert(INSERT, sigdoc)


sigdocBtn = Button(stepTwo, text="Browse ...", command=clicked_sigdoc)
sigdocBtn.grid(row=0, column=6, sticky='E', padx=5, pady=2)

step = LabelFrame(stepTwo, text="Enter the public key: ")
step.grid(row=1, columnspan=8, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

nLbl = Label(step, text="n:")
nLbl.grid(row=0, column=0, padx=2)

nTxt = Entry(step, width=20)
nTxt.grid(row=0, column=1, sticky='W', padx=2)

temp05Lbl = Label(step, width=5)
temp05Lbl.grid(row=0, column=2, sticky='WE', padx=10)

dLbl = Label(step, text="d:")
dLbl.grid(row=0, column=3, padx=2)

dTxt = Entry(step, width=20)
dTxt.grid(row=0, column=4, sticky='W', padx=2, pady=2)


def clicked_acc():
    f1 = open(sigdocTxt.get(), 'r')
    sign_doc = f1.read()
    sign_doc_len = len(sign_doc)
    f1.close()

    f1 = open(sigdocTxt.get(), 'r')
    idx = 0
    list_sd = []
    count = 0
    while idx != sign_doc_len:
        temp = f1.readline()
        list_sd.append(temp)
        idx = f1.tell()
        if(temp[len(temp)-1] == "\n"):
            # sign_doc_len += 1
            count += 1
    f1.close()

    idx_sign = len(list_sd) - 1
    sign_txt = list_sd[idx_sign]

    sign_len = len(sign_txt)
    doc_len = sign_doc_len - sign_len - 1 - count
    f1 = open(sigdocTxt.get(), 'r')
    document_txt = f1.read(doc_len)
    f1.close()

    if int(nTxt.get()) != n or int(dTxt.get()) != d:
        messagebox.showinfo(
            'Message', '\nPublic Key is Invalid. Please try again!')
    else:
        key.n = int(nTxt.get())
        key.d = int(dTxt.get())

        document_hash = key.decrypt(sign_txt)
        h1 = SHA.new()
        doc_text = bytes(document_txt, 'utf-8')
        h1.update(doc_text)
        document_h = h1.hexdigest()

        if document_hash == document_h:
            messagebox.showinfo('Message', '\nDocument Trusted!')
        else:
            messagebox.showinfo('Message', '\nDocument Trusted!')


accBtn = Button(stepTwo, text="Accuracy", command=clicked_acc)
accBtn.grid(row=1, column=6, sticky='E', padx=5, pady=2)

window.mainloop()

# ------------------------------------------
# Test
# Văn bản: This is the text
# Khóa cá nhân: n = 15, e = 11
# Khóa công khai: n = 15, d = 3
# Chữ ký số dưới dạng hex (hệ thập lục phân)
