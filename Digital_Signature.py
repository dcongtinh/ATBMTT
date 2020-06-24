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
        # Nếu plain_txt (giá trị băm) chứa cả số và chữ hoặc bắt đầu bằng "0"
        if plain_txt[0] == "0" or find == "" or len(find) != 1:
            # Chuyển từng ký tự của giá trị băm sang số thứ tự tương ứng trong bảng mã ASCII
            # (vd: A-> 065)  và thêm vào chuỗi plain
            plain = ""
            for i in plain_txt:
                if ord(i) < 10:
                    str_ord = "00" + str(ord(i))
                if ord(i) >= 10 and ord(i) < 100:
                    str_ord = "0" + str(ord(i))
                if ord(i) >= 100:
                    str_ord = str(ord(i))
                plain = plain.__add__(str_ord)
            # Mã hóa từng ký tự trong chuỗi plain và thêm vào chuỗi cipher
            cipher = "0x"
            for i in plain:
                en_i = self.encrypt_i(int(i))
                hex_i = hex(en_i)
                for j in range(2, len(hex_i)):
                    cipher = cipher.__add__(hex_i[j])
            return cipher
        # Nếu plain_txt (giá trị băm) chỉ chứa số và không bắt dầu bằng "0",
        # mã hóa bằng phương thức encrypt_i()
        else:
            return self.encrypt_i(int(find_txt))

    # Giải mã chuỗi ký tự kiểu str
    def decrypt(self, cipher_txt):
        find = re.findall(r'[0-9]+', cipher_txt)
        find_txt = ''.join(find)
        # Nếu cipher_txt (mật mã) chứa cả số và chữ hoặc bắt đầu bằng “0”
        if cipher_txt[0] == "0" or find == "" or len(find) != 1:
            # Bắt đầu bằng ký tự thứ 3 (bỏ 0x) chuyển từng ký tự của mật mã sang kiểu thập phân,
            # giải mật và thêm vào chuỗi result
            result = ""
            for i in range(2, len(cipher_txt)):
                dec_i = int(cipher_txt[i], 16)
                de_i = self.decrypt_i(dec_i)
                result = result.__add__(str(de_i))
            # Chia chuỗi result thành nhóm  3 (các chuỗi gồm 3 ký tự liên tiếp nhau trong chuỗi result),
            # loại bỏ những ký tự 0 ở đầu từng chuỗi và chuyển lại thành kiểu ký tự
            # (Vd: 065 -> 65 -> A) và thêm vào chuỗi res
            def group_adjacent(a, k): return list(zip(*([iter(a)] * k)))
            text_i = group_adjacent(result, 3)
            res = ""
            for i in text_i:
                txt_i = ''.join(i)
                res += chr(int(txt_i.lstrip("0")))
            return res
        # Nếu cipher_txt (mật mã) chỉ chứa số và không bắt dầu bằng “0”,
        # giải mã bằng phương thức decrypt_i()
        else:
            return self.decrypt_i(int(find_txt))


#---------------------------------Giao diện-----------------------------------#
window = Tk()
window.title("Sign the document")

main_container = Frame(window)
main_container.pack(side="top", fill="both", expand=True)

#------Ký văn bản-------#
n = 15
e = 11
d = 3
key = RSA(n, e, d)

stepOne = LabelFrame(main_container, text=" Enter File Details: ")
stepOne.grid(row=0, columnspan=20, sticky='W',
             padx=10, pady=10, ipadx=10, ipady=10)


def clicked_inFile():
    inFile = filedialog.askopenfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    inFileTxt.delete(0, END)
    inFileTxt.insert(INSERT, inFile)


def clicked_outFile():
    outFile = filedialog.asksaveasfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    outFileTxt.delete(0, END)
    outFileTxt.insert(INSERT, outFile)


# Input
inFileLbl = Label(stepOne, text="Select the File (Path):")
inFileLbl.grid(row=0, column=0, sticky='E', padx=5, pady=2)

inFileTxt = Entry(stepOne)
inFileTxt.grid(row=0, column=1, columnspan=14, sticky="WE", pady=2)

inFileBtn = Button(stepOne, text="Browse ...", command=clicked_inFile)
inFileBtn.grid(row=0, column=15, sticky='W', padx=5, pady=2)

# Output
outFileLbl = Label(stepOne, text="Save File to (Path):")
outFileLbl.grid(row=1, column=0, sticky='E', padx=5, pady=2)

outFileTxt = Entry(stepOne)
outFileTxt.grid(row=1, column=1, columnspan=8, sticky="WE", pady=2)

outFileBtn = Button(stepOne, text="Browse ...", command=clicked_outFile)
outFileBtn.grid(row=1, column=9, sticky='W', padx=5, pady=2)


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

    messagebox.showinfo('Message', 'Finish')


okBtn = Button(stepOne, text="OK", command=clicked_OK)
okBtn.grid(row=3, columnspan=10, sticky='WE', padx=5, pady=2)


#----------Xác thực văn bản đã được ký----------#
stepTwo = LabelFrame(main_container, text=" Validate text: ")
stepTwo.grid(row=2, columnspan=20, sticky='W',
             padx=5, pady=5, ipadx=5, ipady=5)

sigdocLbl = Label(stepTwo, text="Signed document (Path):")
sigdocLbl.grid(row=3, column=0, sticky='W', padx=5, pady=2)

sigdocTxt = Entry(stepTwo)
sigdocTxt.grid(row=3, column=1, columnspan=6, sticky='WE', padx=5, pady=2)


def clicked_sigdoc():
    sigdoc = filedialog.askopenfilename(filetypes=(
        ("Text files", "*.txt"), ("all files", "*.*")))
    sigdocTxt.delete(0, END)
    sigdocTxt.insert(INSERT, sigdoc)


sigdocBtn = Button(stepTwo, text="Browse ...", command=clicked_sigdoc)
sigdocBtn.grid(row=3, column=7, sticky='W', padx=5, pady=2)

step = LabelFrame(stepTwo, text="Enter the public key: ")
step.grid(row=4, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

nLbl = Label(step, text="n:")
nLbl.grid(row=0, column=1, sticky='W')

nTxt = Entry(step)
nTxt.grid(row=0, column=2, sticky='E', padx=2, pady=2)

dLbl = Label(step, text="d:")
dLbl.grid(row=0, column=6, padx=2)

dTxt = Entry(step)
dTxt.grid(row=0, column=7, sticky='E', padx=2, pady=2)


def clicked_acc():
    f1 = open(sigdocTxt.get(), 'r')
    sign_doc = f1.read()
    sign_doc_len = len(sign_doc)
    f1.close()
    # Đọc từng hàng của văn bản chứa chữ ký số -> lưu vào list_sd -> chuỗi ở vị trí cuối list là chữ ký số
    f1 = open(sigdocTxt.get(), 'r')
    idx = 0
    list_sd = []
    count = 0
    while idx != sign_doc_len:
        temp = f1.readline()
        list_sd.append(temp)
        idx = f1.tell()
        if temp[len(temp)-1] == "\n":
            sign_doc_len += 1
            count += 1
    f1.close()
    # Tách chữ ký số và văn bản ra gán vào sign_txt (chuỗi chữ ký số) và document_txt (chuỗi văn bản)
    idx_sign = len(list_sd) - 1
    sign_txt = list_sd[idx_sign]

    sign_len = len(sign_txt)

    doc_len = sign_doc_len - sign_len - 1 - count
    f1 = open(sigdocTxt.get(), 'r')
    document_txt = f1.read(doc_len)
    f1.close()
    # Nếu nhập sai khóa công khai thông báo nhập lại
    if int(nTxt.get()) != n or int(dTxt.get()) != d:
        messagebox.showinfo('Message', 'Sai khoa cong khai. Nhap lai')
    else:
        key.n = int(nTxt.get())
        key.d = int(dTxt.get())
        # Giải mã chữ ký số và băm văn bản
        document_hash = key.decrypt(sign_txt)
        h1 = SHA.new()
        doc_text = bytes(document_txt, 'utf-8')
        h1.update(doc_text)
        document_h = h1.hexdigest()
        # Kiểm tra xem có trùng khớp không và thông báo kết quả
        if document_hash == document_h:
            messagebox.showinfo('Message', 'Van ban dang tin cay')
        else:
            messagebox.showinfo('Message', 'Van ban khong dang tin')


accBtn = Button(stepTwo, text="Accuracy", command=clicked_acc)
accBtn.grid(row=4, column=7, sticky='W', padx=5, pady=5)

window.mainloop()

# ------------------------------------------
# Test
# Văn bản: This is the text
# Khóa cá nhân: n = 15, e = 11
# Khóa công khai: n = 15, d = 3
# Chữ ký số dưới dạng hex (hệ thập lục phân)
