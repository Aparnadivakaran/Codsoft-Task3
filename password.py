import tkinter as tk
from tkinter import messagebox
import random
import string

def generate_password(length):
    all_characters = ''
    if lowercase_var.get():
        all_characters += string.ascii_lowercase
    if uppercase_var.get():
        all_characters += string.ascii_uppercase
    if digits_var.get():
        all_characters += string.digits
    if punctuation_var.get():
        all_characters += string.punctuation
    if length < 8:
        messagebox.showerror("Error", "Password length must be at least 8 characters")
        return
    if not all_characters:
        messagebox.showerror("Error", "At least one character set must be selected")
        return
    password = ''.join(random.choice(all_characters) for i in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def copy_password():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Success", "Password copied to clipboard")

root = tk.Tk()
root.title("Password Generator")
root.configure(background='light blue')
root.geometry("400x400")

length_label = tk.Label(root, text="Password Length:", bg='light blue', fg='#000000') 
length_label.pack()

length_entry = tk.Entry(root, width=10, bg='#ffffff', fg='#000000') 
length_entry.pack(pady=(5, 20))  

lowercase_var = tk.BooleanVar()
uppercase_var = tk.BooleanVar()
digits_var = tk.BooleanVar()
punctuation_var = tk.BooleanVar()

tk.Checkbutton(root, text="Include lowercase letters", variable=lowercase_var, bg='light blue', fg='#00698f').pack(pady=(0, 5))  
tk.Checkbutton(root, text="Include uppercase letters", variable=uppercase_var, bg='light blue', fg='#00698f').pack(pady=(0, 5))  
tk.Checkbutton(root, text="Include digits", variable=digits_var, bg='light blue', fg='#00698f').pack(pady=(0, 5)) 
tk.Checkbutton(root, text="Include punctuation", variable=punctuation_var, bg='light blue', fg='#00698f').pack(pady=(0, 10))  

generate_button = tk.Button(root, text="Generate Password", command=lambda: generate_password(int(length_entry.get())), bg='#007bff', fg='#ffffff')  # button color and text color
generate_button.pack(pady=(5, 20)) 

password_label = tk.Label(root, text="Generated Password:", bg='light blue', fg='#000000')
password_label.pack()

password_entry = tk.Entry(root, width=40, bg='#ffffff', fg='#000000')
password_entry.pack(pady=(5, 20)) 

copy_button = tk.Button(root, text="Copy Password", command=copy_password, bg='#007bff', fg='#ffffff')
copy_button.pack(pady=(5, 20)) 

root.mainloop()