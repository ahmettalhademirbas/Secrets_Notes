import tkinter
import base64
from PIL import Image, ImageTk
from tkinter import messagebox

window = tkinter.Tk()
window.title("Secret Notes")
window.geometry("400x650")

frame = tkinter.Frame()
frame.config(pady=30, padx=30)
frame.pack()

img = (Image.open("top_secret.png"))
resized_img = img.resize((100, 100), Image.LANCZOS)
new_image = ImageTk.PhotoImage(resized_img)

label = tkinter.Label(frame, image=new_image)
label.pack()

entry_label = tkinter.Label(text="Enter Your Title", font=('Arial', 10, 'normal'))
entry_label.pack()

title_entry = tkinter.Entry(width=40)
title_entry.pack()

text_label = tkinter.Label(text="Enter Your Secret", font=('Arial', 10, 'normal'))
text_label.pack()

secret_text = tkinter.Text(width=40, height=13)
secret_text.pack()

key_label = tkinter.Label(text="Enter Master Key", font=('Arial', 10, 'normal'))
key_label.pack()

key_entry = tkinter.Entry(width=40)
key_entry.pack()


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def write_file():
    global encrypt_secret
    title_name = title_entry.get()
    secret = secret_text.get(1.0, tkinter.END)
    key = key_entry.get()

    if len(title_name) == 0 or len(secret) == 0 or len(key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")

    else:
        encrypt_secret = encode(key, secret)
        try:
            with open("mysecret.txt", "a") as f:
                f.write(f"\n{title_name}\n{str(encrypt_secret)}")
        except:
            with open("mysecret.txt", "w") as f:
                f.write(f"\n{title_name}\n{str(encrypt_secret)}")
        finally:
            title_entry.delete(0, tkinter.END)
            secret_text.delete(1.0, tkinter.END)
            key_entry.delete(0, tkinter.END)


encrypt_button = tkinter.Button(text="Save & Encrypt", command=write_file)
encrypt_button.pack()


def decrypt():
    key = key_entry.get()
    secret = secret_text.get(1.0, tkinter.END)
    if len(key) == 0 or len(secret) == 0:
        messagebox.showinfo(title="Errors!", message="Please enter all info")
    else:
        try:
            string_decoding = decode(key, secret)
            secret_text.delete(1.0, tkinter.END)
            secret_text.insert(1.0, string_decoding)
        except:
            messagebox.showinfo(title="Error", message="This text already decrypted!")


decrypt_button = tkinter.Button(text="Decrypt", command=decrypt)
decrypt_button.pack()

window.mainloop()
