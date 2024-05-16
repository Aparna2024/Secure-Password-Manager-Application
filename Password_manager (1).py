import tkinter as tk
from tkinter import messagebox
import sqlite3
import secrets
import hashlib
from tkinter import simpledialog
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyperclip
from tkinter.constants import W  # Import the W constant

# Flag variable to indicate if the password was generated randomly
password_generated = False

# Track the currently logged-in user
current_user = None 

#stores the master password entered by the user 
master = None

#salt used for user-specific key derivation
Usalt = None

#derived key from the master password for encryption and decryption
Mkey = None

reset_window = None


# Key derivation function parameters
KDF_SALT_SIZE = 16

# Adjust as needed for desired security level
KDF_ITERATIONS = 100000  

#function to reset the password for given username 
def reset_password_screen(username):
    #function to handle the password reset process
    def reset_password():
        new_password = new_password_entry.get()
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        
        stored_password = user[1]
        
        salt = user[3]
        hashed_new_password = hashlib.sha256((new_password + salt).encode('utf-8')).hexdigest()


        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE users SET hashed_password=? WHERE username=?", (hashed_new_password, username))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password reset successful.")
        reset_window.destroy()

    reset_window = tk.Toplevel(root)
    reset_window.title("Reset Password")

    new_password_label = tk.Label(reset_window, text="New Password:")
    new_password_label.grid(row=0, column=0, padx=10, pady=5)
    new_password_entry = tk.Entry(reset_window, show="*")
    new_password_entry.grid(row=0, column=1, padx=10, pady=5)

    reset_button = tk.Button(reset_window, text="Reset Password", command=reset_password)
    reset_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# Function to derive key from hashed master password
def derive_key_from_hashed_master_password(hashed_master_password, salt):
    """
    Derives a cryptographic key from a hashed master password using PBKDF2.

        hashed_master_password (str): The hashed master password to derive the key from.
        salt (bytes): The salt used in the key derivation process.

    Returns:
        bytes: The derived cryptographic key.

    Note:
        PBKDF2 (Password-Based Key Derivation Function 2) is used for deriving keys from passwords.
        It applies a hash function repeatedly to the input along with a salt to produce a derived key.
        The derived key has a fixed length specified by 'dkLen' parameter. 32 bytes (256 bits)
            using it for security purposes 
        'KDF_ITERATIONS' is the number of iterations used in the key derivation process.
        The longer the iterations, the more secure but slower the key derivation process.
        
        encode() method is used to convert a string to bytes using a specified encoding
    """
    return PBKDF2(hashed_master_password.encode(), salt, dkLen=32, count=KDF_ITERATIONS)

# Function to derive key from master password
def derive_key(master_password, salt):
    """
    Derives a key from a master password and a salt using PBKDF2 algorithm.

    Parameters:
    - master_password (str): The master password from which the key is derived.
    - salt (bytes): Random bytes used as a cryptographic salt for key derivation.

    Returns:
    - bytes: The derived key with a length of 32 bytes.

    Note:
    - PBKDF2 (Password-Based Key Derivation Function 2) is used for key derivation.
    - The master_password is first encoded to bytes before being used in the derivation.
    - The count parameter specifies the number of iterations for the key derivation process.
    """
    
    return PBKDF2(master_password.encode(), salt, dkLen=32, count=KDF_ITERATIONS)

# Function to encrypt data using AES-GCM
def encrypt_data(data, key):
    """
    data(str): the plaintext data to be encrypted
    key (bytes): the encryption key used to encrypt the data, should be a bytes-like
    
    returns:
        bytes: the encrypted data, includes nonce, ciphertext and authentication tag
    
    """
    nonce = get_random_bytes(12)  # Generate a random nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return nonce + ciphertext + tag

# Function to decrypt data using AES-GCM
def decrypt_data(ciphertext, key):
    """
        Decrypts the ciphertext using AES-GCM mode with the provided key
        
            ciphertext (bytes) : The encrypted data to decrypt
            key (bytes) : the key used for decryption
            
        returns:
            str: which is the decrypted plain text 
    
    """
    
    nonce = ciphertext[:12]  # Extract nonce from ciphertext
    tag = ciphertext[-16:]  # Extract tag from ciphertext
    ciphertext = ciphertext[12:-16]  # Extract ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def copy_password(password):
    pyperclip.copy(password)
    
def search_passwords(query, passwords, key):
    filtered_passwords = []
    for password in passwords:
        if query.lower() in password[0].lower() or query.lower() in password[1].lower():  # Search by website or username
            filtered_passwords.append(password)
    display_passwords_window(filtered_passwords)

    
def add_password():
    global password_generated
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    # Check if password was generated randomly
    if not password_generated:
        # If password was entered manually, enforce requirements
        if not (any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~" for c in password) and
                password != username):
            status_label.config(text="Password must contain at least one uppercase letter, one digit, one special character, and be different from the username.", fg="red")

            return
        else:
            password_entry.config(show="*")  # Mask the password
            status_label.config(text="")  # Reset the status label
    if website and username:
        # Derive key from master password and salt
        key = derive_key(master, Usalt)
        # Encrypt password
        encrypted_password = encrypt_data(password, key)
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("INSERT INTO passwords (website, username, password, user_username) VALUES (?, ?, ?, ?)", (website, username, encrypted_password, current_user))
        conn.commit()
        conn.close()
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        password_generated = False  # Reset the flag
    else:
        status_label.config(text="Please fill in all fields", fg="red")
        
def generate_and_display_random_password():
    global password_generated
    # Generate a random password
    random_password = generate_random_password()   
    # Display the generated password in the password entry field without masking it
    password_entry.delete(0, tk.END)
    password_entry.insert(0, random_password)
    password_entry.config(show="")  # Show the password as plain text
    # Set the flag to indicate password was generated randomly
    password_generated = True

def retrieve_passwords():
    global current_user
    if current_user:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT * FROM passwords WHERE user_username=?", (current_user,))
        passwords = c.fetchall()
        conn.close()
        if passwords:
            display_passwords_window(passwords)
        else:
            messagebox.showinfo("No Passwords", "There are no passwords stored yet.")
    else:
        messagebox.showinfo("Not Logged In", "Please login to retrieve passwords.")

def generate_random_password(length=12):
    # Define character sets for generating passwords
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    special_characters = "!@#$%^&*()_+-=[]{}|;:,.<>?~"
    # Combine character sets to form the full set of characters to choose from
    all_characters = alphabet + digits + special_characters
    # Generate a random password by choosing characters from the full set
    password = ''.join(secrets.choice(all_characters) for _ in range(length))
    return password

#displays the saved passwords window
def display_passwords_window(passwords):
    passwords_window = tk.Toplevel(root)
    passwords_window.title("Stored Passwords")
    key = derive_key(master, Usalt)
    def display_all_passwords():
        for widget in passwords_window.winfo_children():
            widget.destroy()        
        # Display all passwords
        for i, password in enumerate(passwords):
            website_label = tk.Label(passwords_window, text=f"Website: {password[0]}")
            website_label.grid(row=i, column=0, padx=10, pady=5, sticky="w")
            username_label = tk.Label(passwords_window, text=f"Username: {password[1]}")
            username_label.grid(row=i, column=1, padx=10, pady=5, sticky="w")
            password_label = tk.Label(passwords_window, text=f"Password: {decrypt_data(password[2], key)}")
            password_label.grid(row=i, column=2, padx=10, pady=5, sticky="w")
            edit_button = tk.Button(passwords_window, text="Edit", command=lambda idx=i: edit_password(passwords_window, passwords[idx]))
            edit_button.grid(row=i, column=3, padx=5, pady=5)
            delete_button = tk.Button(passwords_window, text="Delete", command=lambda idx=i: delete_password(passwords_window, passwords[idx]))
            delete_button.grid(row=i, column=4, padx=5, pady=5)
            copy_button = tk.Button(passwords_window, text="Copy", command=lambda pwd=password[2]: copy_password(decrypt_data(pwd, key)))
            copy_button.grid(row=i, column=5, padx=5, pady=5)
    # Display all passwords initially
    display_all_passwords()

def edit_password(passwords_window, password):
    edit_window = tk.Toplevel(passwords_window)
    edit_window.title("Edit Password")
    key = derive_key(master, Usalt)
    
    # Define a function to save the edited password
    def save_password_edit():
        new_website = website_entry.get()
        new_username = username_entry.get()
        new_password = password_entry.get()

        # Check if the new password meets the requirements
        if not (any(c.isupper() for c in new_password) and
                any(c.isdigit() for c in new_password) and
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~" for c in new_password) and
                new_password != new_username):
            messagebox.showerror("Error", "Password must contain at least one uppercase letter, one digit, one special character, and be different from the username.")
            return

        # Encrypt new password
        encrypted_new_password = encrypt_data(new_password, key)

        # Update password in the database
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("UPDATE passwords SET website=?, username=?, password=? WHERE website=? AND username=? AND password=?",
                  (new_website, new_username, encrypted_new_password, password[0], password[1], password[2]))
        conn.commit()
        conn.close()
        edit_window.destroy()
        passwords_window.destroy()
        retrieve_passwords()
    
    # Create GUI elements for editing password
    website_label = tk.Label(edit_window, text="Website:")
    website_label.grid(row=0, column=0, padx=10, pady=5)
    website_entry = tk.Entry(edit_window)
    website_entry.grid(row=0, column=1, padx=10, pady=5)
    website_entry.insert(tk.END, password[0])
    
    username_label = tk.Label(edit_window, text="Username:")
    username_label.grid(row=1, column=0, padx=10, pady=5)
    username_entry = tk.Entry(edit_window)
    username_entry.grid(row=1, column=1, padx=10, pady=5)
    username_entry.insert(tk.END, password[1])
    
    password_label = tk.Label(edit_window, text="Password:")
    password_label.grid(row=2, column=0, padx=10, pady=5)
    password_entry = tk.Entry(edit_window)
    password_entry.grid(row=2, column=1, padx=10, pady=5)
    password_entry.insert(tk.END, decrypt_data(password[2], key))
    
    save_button = tk.Button(edit_window, text="Save", command=save_password_edit)
    save_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

def save_password(edit_window, passwords_window, old_password, new_website, new_username, new_password):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("UPDATE passwords SET website=?, username=?, password=? WHERE website=? AND username=? AND password=?",
              (new_website, new_username, new_password, old_password[0], old_password[1], old_password[2]))
    conn.commit()
    conn.close()
    edit_window.destroy()
    passwords_window.destroy()
    retrieve_passwords()


def delete_password(passwords_window, password):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE website=? AND username=? AND password=?",
              (password[0], password[1], password[2]))
    conn.commit()
    conn.close()
    passwords_window.destroy()
    retrieve_passwords()

def forgot_password_clicked():
    def reset_password():
        username = username_reset_entry.get()
        favorite_food = favorite_food_reset_entry.get()
        elementary_school = elementary_school_reset_entry.get()

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data:
            stored_favorite_food_hash = user_data[4]
            stored_elementary_school_hash = user_data[5]

            entered_favorite_food_hash = hashlib.sha256(favorite_food.encode()).hexdigest()
            entered_elementary_school_hash = hashlib.sha256(elementary_school.encode()).hexdigest()

            if stored_favorite_food_hash == entered_favorite_food_hash and stored_elementary_school_hash == entered_elementary_school_hash:
                reset_password_screen(username)
                # Close the reset window along with the security question entries
                reset_window.destroy()
            else:
                messagebox.showerror("Error", "Incorrect security question answers. Please try again.")
        else:
            messagebox.showerror("Error", "User not found.")


    reset_window = tk.Toplevel(root)
    reset_window.title("Reset Password")

    username_reset_label = tk.Label(reset_window, text="Username:")
    username_reset_label.grid(row=0, column=0, padx=10, pady=5)
    username_reset_entry = tk.Entry(reset_window)
    username_reset_entry.grid(row=0, column=1, padx=10, pady=5)

    favorite_food_reset_label = tk.Label(reset_window, text="Favorite Food:")
    favorite_food_reset_label.grid(row=1, column=0, padx=10, pady=5)
    favorite_food_reset_entry = tk.Entry(reset_window)
    favorite_food_reset_entry.grid(row=1, column=1, padx=10, pady=5)

    elementary_school_reset_label = tk.Label(reset_window, text="Elementary School Name:")
    elementary_school_reset_label.grid(row=2, column=0, padx=10, pady=5)
    elementary_school_reset_entry = tk.Entry(reset_window)
    elementary_school_reset_entry.grid(row=2, column=1, padx=10, pady=5)

    reset_button = tk.Button(reset_window, text="Reset Password", command=reset_password)
    reset_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")



def verify_security_questions(username_entry, favorite_food_entry, elementary_school_entry):
    # Retrieve data from entry fields
    username = username_entry.get()
    favorite_food = favorite_food_entry.get()
    elementary_school = elementary_school_entry.get()

    # Connect to the database and retrieve user data
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Fetch user data including hashed answers for security questions
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user_data = c.fetchone()

    # Check if the user exists
    if user_data:
        try:
            # Retrieve stored hashed answers
            stored_favorite_food_hash = user_data[4]
            stored_elementary_school_hash = user_data[5]

            # Hash the entered answers for comparison
            entered_favorite_food_hash = hashlib.sha256(favorite_food.encode()).hexdigest()
            entered_elementary_school_hash = hashlib.sha256(elementary_school.encode()).hexdigest()

            # Compare hashed answers
            if stored_favorite_food_hash == entered_favorite_food_hash and stored_elementary_school_hash == entered_elementary_school_hash:
                # If answers match, open the password reset screen
                reset_password_screen()
            else:
                messagebox.showerror("Error", "Incorrect security question answers. Please try again.")

        except IndexError:
            messagebox.showerror("Error", "Unexpected database response. Please try again.")
    else:
        messagebox.showerror("Error", "User not found.")

    conn.close()
# Function to show the signup window
def show_signup_window():
    login_window.withdraw()  # Hide the login window
    signup_window.deiconify()  # Show the signup window

# Function to handle signup process
def signup_clicked():
    username = username_signup_entry.get()
    password = password_signup_entry.get()
    master_password = master_password_signup_entry.get()
    favorite_food = favorite_food_entry.get()
    elementary_school = elementary_school_entry.get()
    if username and password and master_password and favorite_food and elementary_school:
        # Check if username already exists
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        existing_user = c.fetchone()
        if existing_user:
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")
            conn.close()
            return
        # Check password requirements
        if (len(password) >= 8 and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~" for c in password) and
            password != username):
            # Generate a random salt
            salt = secrets.token_hex(16)  # Generate a 16-byte (32-character) random salt
            # Combine password and salt, then hash the combined value
            hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
            hashed_master_password = hashlib.sha256((master_password + salt).encode('utf-8')).hexdigest()
            # Hash security question answers
            hashed_favorite_food = hashlib.sha256(favorite_food.encode('utf-8')).hexdigest()
            hashed_elementary_school = hashlib.sha256(elementary_school.encode('utf-8')).hexdigest()
            # Store username, hashed password, salt, and hashed security question answers in the database
            c.execute("INSERT INTO users (username, hashed_password, hashed_master_password, salt, favorite_food, elementary_school) VALUES (?, ?, ?, ?, ?, ?)",
                      (username, hashed_password, hashed_master_password, salt, hashed_favorite_food, hashed_elementary_school))
            conn.commit()
            conn.close()
            messagebox.showinfo("Signup Successful", "You have successfully signed up!")
            signup_window.withdraw()
            login_window.deiconify()
        else:
            messagebox.showerror("Error", "Password must be at least 8 characters long, contain at least one uppercase letter, one digit, one special character, and be different from the username.")
    else:
        messagebox.showerror("Error", "Please fill in all fields.")
# Function to handle login process
def login_clicked():
    global current_user
    global master
    global Usalt
    global Mkey
    username = username_login_entry.get()
    password = password_login_entry.get()
    
    if username and password:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        
        if user:
            # Retrieve the hashed password and salt from the database
            stored_password = user[1]
            salt = user[3]
            
            # Combine entered password with stored salt, then hash the combined value
            entered_hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
            
            # Compare the hashed passwords
            if entered_hashed_password == stored_password:
                master_password = simpledialog.askstring("Login", "Enter your master password:", show='*')
                entered_hashed_master_password = hashlib.sha256((master_password + salt).encode('utf-8')).hexdigest()
                
                while entered_hashed_master_password != user[2]:
                    messagebox.showerror("Error", "Invalid master password")
                    master_password = simpledialog.askstring("Login", "Enter your master password:", show='*')
                    entered_hashed_master_password = hashlib.sha256((master_password + salt).encode('utf-8')).hexdigest()            
                
                Mkey = derive_key_from_hashed_master_password(entered_hashed_password, salt)
                master = master_password
                Usalt = salt
                current_user = username
                messagebox.showinfo("Login Successful", "You have successfully logged in!")
                login_window.withdraw()
                root.deiconify()
            else:
                messagebox.showerror("Error", "Invalid username or password.")
        else:
            messagebox.showerror("Error", "Invalid username or password.")
    else:
        messagebox.showerror("Error", "Please fill in all fields.")

        
# Function to handle logout process
def logout():
    global current_user
    global master
    global Usalt
    current_user = None
    master = None
    Usalt = None
    # Clear the entry fields in the login window
    username_login_entry.delete(0, tk.END)
    password_login_entry.delete(0, tk.END)
    root.withdraw()  # Hide the main window
    login_window.deiconify()  # Show the login window

# Create the main window
root = tk.Tk()
root.title("Password Manager")

# Hide the main window initially
root.withdraw()

# Create database if not exists for passwords
conn = sqlite3.connect('passwords.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (website text, username text, password BLOB, user_username text)''')  # Add user_username column
conn.commit()
conn.close()

# Create database if not exists for users
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, hashed_password TEXT, hashed_master_password TEXT, salt TEXT,
             favorite_food TEXT, elementary_school TEXT)''')
conn.commit()
conn.close()

# Create GUI elements
website_label = tk.Label(root, text="Website:")
website_label.grid(row=0, column=0, padx=10, pady=5)
website_entry = tk.Entry(root)
website_entry.grid(row=0, column=1, padx=10, pady=5)
username_label = tk.Label(root, text="Username:")
username_label.grid(row=1, column=0, padx=10, pady=5)
username_entry = tk.Entry(root)
username_entry.grid(row=1, column=1, padx=10, pady=5)
password_label = tk.Label(root, text="Password:")
password_label.grid(row=2, column=0, padx=10, pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=2, column=1, padx=10, pady=5)

add_button = tk.Button(root, text="Add Password", command=add_password)
add_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
generate_password_button = tk.Button(root, text="Generate Random Password", command=generate_and_display_random_password)
generate_password_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
retrieve_button = tk.Button(root, text="Retrieve Passwords", command=retrieve_passwords)
retrieve_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
status_label = tk.Label(root, text="", fg="red")
status_label.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

logout_button = tk.Button(root, text="Logout", command=logout)
logout_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# Create signup window
signup_window = tk.Toplevel(root)
signup_window.title("Signup")
signup_window.withdraw()

username_signup_label = tk.Label(signup_window, text="Username:")
username_signup_label.grid(row=0, column=0, padx=10, pady=5)
username_signup_entry = tk.Entry(signup_window)
username_signup_entry.grid(row=0, column=1, padx=10, pady=5)

password_signup_label = tk.Label(signup_window, text="Password:")
password_signup_label.grid(row=1, column=0, padx=10, pady=5)
password_signup_entry = tk.Entry(signup_window, show="*")
password_signup_entry.grid(row=1, column=1, padx=10, pady=5)

master_password_signup_label = tk.Label(signup_window, text="Master Password:")
master_password_signup_label.grid(row=2, column=0, padx=10, pady=5)
master_password_signup_entry = tk.Entry(signup_window, show="*")
master_password_signup_entry.grid(row=2, column=1, padx=10, pady=5)

# Modify the UI to include entry fields for security questions
favorite_food_label = tk.Label(signup_window, text="Favorite Food:")
favorite_food_label.grid(row=3, column=0, sticky=W)  # Adjust row index
favorite_food_entry = tk.Entry(signup_window, width=30)
favorite_food_entry.grid(row=3, column=1, padx=5, pady=5)  # Adjust row index

elementary_school_label = tk.Label(signup_window, text="Elementary School Name:")
elementary_school_label.grid(row=4, column=0, sticky=W)  # Adjust row index
elementary_school_entry = tk.Entry(signup_window, width=30)
elementary_school_entry.grid(row=4, column=1, padx=5, pady=5)  # Adjust row index

signup_button = tk.Button(signup_window, text="Signup", command=signup_clicked)
signup_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# Create login window
login_window = tk.Toplevel(root)
login_window.title("Login")
username_login_label = tk.Label(login_window, text="Username:")
username_login_label.grid(row=0, column=0, padx=10, pady=5)
username_login_entry = tk.Entry(login_window)
username_login_entry.grid(row=0, column=1, padx=10, pady=5)
password_login_label = tk.Label(login_window, text="Password:")
password_login_label.grid(row=1, column=0, padx=10, pady=5)
password_login_entry = tk.Entry(login_window, show="*")
password_login_entry.grid(row=1, column=1, padx=10, pady=5)
login_button = tk.Button(login_window, text="Login", command=login_clicked)
login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
signup_login_button = tk.Button(login_window, text="Signup", command=show_signup_window)
signup_login_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
forgot_password_button = tk.Button(login_window, text="Forgot Password", command=forgot_password_clicked)
forgot_password_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

root.mainloop()