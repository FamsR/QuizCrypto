import tkinter as tk
from tkinter import filedialog, messagebox, StringVar
import numpy as np

# Initialize file_path
file_path = ""

# Vigenere Encryption and Decryption
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            enc_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += enc_char
            key_index += 1
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ""
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            dec_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
            # Preserve original character case
            if char.islower():
                plaintext += dec_char.lower()
            else:
                plaintext += dec_char
            key_index += 1
        else:
            plaintext += char  # Preserve non-alphabetic characters

    return plaintext

# Playfair Cipher
def remove_spaces(text):
    return "".join(text.split())

def diagraph(text):
    text = text.lower()
    diagraphs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:  # Last single character
            diagraphs.append(text[i] + 'x')
            break
        if text[i] == text[i + 1]:  # Same letters
            diagraphs.append(text[i] + 'x')
            i += 1
        else:
            diagraphs.append(text[i] + text[i + 1])
            i += 2
    return diagraphs

def generate_key_table(key):
    key = remove_spaces(key).lower()
    key = key.replace('j', 'i')  # Replace 'j' with 'i'
    unique_letters = []
    
    for char in key:
        if char not in unique_letters and char in 'abcdefghiklmnopqrstuvwxyz':
            unique_letters.append(char)
    
    for char in 'abcdefghiklmnopqrstuvwxyz':
        if char not in unique_letters:
            unique_letters.append(char)
    
    return [unique_letters[i:i + 5] for i in range(0, 25, 5)]

def search(matrix, element):
    if element == 'j':
        element = 'i'
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == element:
                return i, j
    return None

def encrypt_playfair(plaintext, key):
    matrix = generate_key_table(key)
    diagraphs = diagraph(remove_spaces(plaintext))
    cipher_text = []

    for pair in diagraphs:
        ele1_x, ele1_y = search(matrix, pair[0])
        ele2_x, ele2_y = search(matrix, pair[1])

        if ele1_x == ele2_x:
            cipher_text.append(matrix[ele1_x][(ele1_y + 1) % 5])
            cipher_text.append(matrix[ele2_x][(ele2_y + 1) % 5])
        elif ele1_y == ele2_y:
            cipher_text.append(matrix[(ele1_x + 1) % 5][ele1_y])
            cipher_text.append(matrix[(ele2_x + 1) % 5][ele2_y])
        else:
            cipher_text.append(matrix[ele1_x][ele2_y])
            cipher_text.append(matrix[ele2_x][ele1_y])

    return ''.join(cipher_text)

def decrypt_playfair(ciphertext, key):
    matrix = generate_key_table(key)
    diagraphs = diagraph(remove_spaces(ciphertext))
    plain_text = []

    for pair in diagraphs:
        ele1_x, ele1_y = search(matrix, pair[0])
        ele2_x, ele2_y = search(matrix, pair[1])

        if ele1_x == ele2_x:
            plain_text.append(matrix[ele1_x][(ele1_y - 1) % 5])
            plain_text.append(matrix[ele2_x][(ele2_y - 1) % 5])
        elif ele1_y == ele2_y:
            plain_text.append(matrix[(ele1_x - 1) % 5][ele1_y])
            plain_text.append(matrix[(ele2_x - 1) % 5][ele2_y])
        else:
            plain_text.append(matrix[ele1_x][ele2_y])
            plain_text.append(matrix[ele2_x][ele1_y])

    result = ''.join(plain_text).replace('x', '')
    return result

# Hill Cipher
# Hill Cipher Functions
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1

def matrix_inverse_mod26(matrix):
    det = int(np.round(np.linalg.det(matrix)))  # Determinant
    det_inv = mod_inverse(det, 26)  # Modular inverse of determinant
    if det_inv == -1:
        raise ValueError("Key matrix has no inverse mod 26")
    
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % 26  # Adjugate matrix
    inverse_matrix = (det_inv * adjugate) % 26
    return inverse_matrix

def get_key_matrix(key):
    k = 0
    key_matrix = [[0] * 3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            key_matrix[i][j] = ord(key[k].upper()) % 65
            k += 1
    return key_matrix

def hill_encrypt(message, key):
    key_matrix = get_key_matrix(key)
    cipher_text = ""

    for i in range(0, len(message), 3):
        block = message[i:i + 3]
        while len(block) < 3:  # Padding
            block += 'X'

        message_vector = [[ord(block[j].upper()) % 65] for j in range(3)]
        cipher_matrix = [[0] for _ in range(3)]

        for r in range(3):
            for c in range(3):
                cipher_matrix[r][0] += key_matrix[r][c] * message_vector[c][0]
            cipher_matrix[r][0] %= 26

        cipher_text += ''.join(chr(cipher_matrix[r][0] + 65) for r in range(3))

    return cipher_text

def hill_decrypt(ciphertext, key):
    key_matrix = get_key_matrix(key)
    inverse_matrix = matrix_inverse_mod26(key_matrix)
    decrypted_text = ""

    for i in range(0, len(ciphertext), 3):
        block = ciphertext[i:i + 3]
        while len(block) < 3:  # Padding
            block += 'X'

        message_vector = [[ord(block[j]) % 65] for j in range(3)]
        plain_matrix = [[0] for _ in range(3)]

        for r in range(3):
            for c in range(3):
                plain_matrix[r][0] += inverse_matrix[r][c] * message_vector[c][0]
            plain_matrix[r][0] %= 26

        decrypted_text += ''.join(chr(plain_matrix[r][0] + 65) for r in range(3))

    return decrypted_text.rstrip('X')  # Remove padding 'X'

# Upload file function
def upload_file():
    global file_path
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        file_label.config(text=f"File Selected: {file_path.split('/')[-1]}")

# Encrypt text function
def encrypt_text():
    key = key_entry.get()
    selected_cipher = cipher_var.get()
    plaintext = plaintext_entry.get("1.0", tk.END).strip()

    if not file_path and not plaintext:
        messagebox.showerror("Error", "Please provide plaintext or select a file.")
        return

    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long.")
        return

    if file_path:
        with open(file_path, 'r') as file:
            plaintext = file.read().replace('\n', '')

    if selected_cipher == "Vigenere":
        result = vigenere_encrypt(plaintext, key)
    elif selected_cipher == "Playfair":
        result = encrypt_playfair(plaintext, key)
    elif selected_cipher == "Hill":
        result = hill_encrypt(plaintext, key[:9])  # Assuming key is at least 9 characters for Hill
    else:
        result = "Invalid Cipher Selected"

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result)

# Decrypt text function
def decrypt_text():
    key = key_entry.get()
    selected_cipher = cipher_var.get()

    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long.")
        return

    ciphertext = result_box.get("1.0", tk.END).strip()

    if selected_cipher == "Vigenere":
        result = vigenere_decrypt(ciphertext, key)
    elif selected_cipher == "Playfair":
        result = decrypt_playfair(ciphertext, key)
    elif selected_cipher == "Hill":
        result = hill_decrypt(ciphertext, key[:9])  # Implement logika dekripsi
    else:
        result = "Invalid Cipher Selected"

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result)

# Setup Tkinter window
root = tk.Tk()
root.title("Cipher Application")
root.configure(bg='lightblue')

# Plaintext input section
plaintext_label = tk.Label(root, text="Enter Plaintext (or upload a file):", bg='lightblue')
plaintext_label.pack()

plaintext_entry = tk.Text(root, height=5, width=50)
plaintext_entry.pack()

# File upload section
file_label = tk.Label(root, text="No file selected", bg='lightblue')
file_label.pack()

upload_button = tk.Button(root, text="Upload .txt File", command=upload_file)
upload_button.pack()

# Key entry
key_label = tk.Label(root, text="Enter Key (min 12 characters):", bg='lightblue')
key_label.pack()

key_entry = tk.Entry(root)
key_entry.pack()

# Cipher selection
cipher_var = StringVar(value="Vigenere")  # Default selection
cipher_label = tk.Label(root, text="Select Cipher:", bg='lightblue')
cipher_label.pack()

cipher_menu = tk.OptionMenu(root, cipher_var, "Vigenere", "Playfair", "Hill")
cipher_menu.pack()

# Encrypt and Decrypt buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

# Result text box
result_box = tk.Text(root, height=20, width=50)
result_box.pack()

# Run the application
root.mainloop()