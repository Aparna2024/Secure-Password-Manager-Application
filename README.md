# Secure-Password-Manager-Application
In this digital age, maintaining strong passwords across various platforms is crucial, as of now evert website and app requires the signup and login to help you track on certain things. For this project, I am implementing a Password Manager Application which is designed to provide users with a secure way to store and retrieve their passwords. This app is convenient and helpful to everyone because it contains features like secure password storage and management for various websites. This app is implemented using Python and Tkinter library in Python for building the GUI. 

**Functional Requirements**
- The Secure Password Manager application can support the creation of multiple user accounts, and each account has their own database of stored passwords after logging in.
- Each individual can create their own account and can change their password using the security question set up that is implemented during signup process.
- The user can store an existing password for a website or application along with username, website name and password.
- The user can generate a strong random password for the certain websites or application they want.
- This app secure protects the passwords, by adding an extra layer of security by encrypting the passwords before storing in the database using AES – 256 and Galois/Counter Mode block cipher and decrypts the password before the user derives
in the same way.
- This application makes sures of the authenticity by implementing the master
password feature where the user sets up one during the signup process, which is hashed and stored in the database and when logging in the user is asked to enter the master password and then that hash value is matched with the initial hash value and if matched then the user can enter the app.
- The master password is also used to derive the key for the AES encryption. The master password is hashed, and the key is derived from this hash value and that key is used for AES encryption and decryption.
- In the password manager screen the user can modify the username, website name and password, and have a delete option, where they can delete the website name, password and username and can copy the password to their clipboard.

Cryptoalgorithms implemented in this project
- master password, which is hashed using SHA-256 algorithm and the key for AES is derived from the hashed password using PBDKF2.
- AES 256 and GCM is used to encrypt and decrypt the saved passwords and since its a symmetric algorithm we use the same key for encryption and decryption that is derived from the hashed master password.
- There is also password hashing involved.
- database used - SQLite

Implementation Details 

**Signup Process**
The signup process/window allows the users to make a new account by providing the text fields, username, password, master password, and security questions like favorite food and elementary school name. Here the password that user sets ups should follow the password requirements, like the password should at least be 8 characters long, should contains at least one uppercase letter, one digit, one special character and shouldn’t be same as username. When the user enters all the fields and clicks on signup button, the code in the background checks the username already exists, if it does, then it displays the message saying that the username exists and it checks the password to see if it meets the password requirements, if all conditions are met then it successfully creates an account for the new user. The master password does not have any requirement because it can be anything like it can be a paraphrase, a word or anything that the user wants it to be and can remember. When the user signs up the password and the master password are saved in the database by securely hashed by the SHA-256 algorithm and the randomly generated salt values so that even if the attacker gets access to the database file, I cannot get the password because they are being stored as hash values.


**Login Process**
The login process acts as an important step because this provides the access control and security for the user accounts. When the user is at the login screen, they have to enter the username and password, in the backend the code will be performing the login validation where the app retrieves the stored hashed password and salt from the database based on the given username, then the entered password and stored salt is combined and then hashed and this is used to compare it with the stored hashed password, it the credentials match, there is another verification step which is the master password verification, the entered master password is hashed with the salt retrieved from database and then used as a comparison with the stored hashed master password, if it matches then the user can view the password manager screen.

**Password Storage**
In the Secure Password Manager application the stored password are secured using cryptographic techniuuqes. In this app, the PBKDF2 algorithm is used to derive keys from the hashed master password, this algorithm applies a pseudorandom function, like SHA-256 and iteratively generates a secure cryptographic key, thus is makes brute-force attacks more
difficult and time consuming. For encrypting and decrypting the user data, I have used AES algorithm in the GCM, as it provides authenticated encryption by making sure that both confidentiality and integrity of the data is achieved. Since AES is symmetric algorithm same key is used for encryption and decryption. In the user’s interface, when displaying the stored passwords, the encrypted password data is decrypted using the derived key before showing to the user, this make sures that the passwords are only accessible in their decrypted form during the session and never stored in plaintext. To view the saved passwords, we can click on the retrieve passwords button, which has features like edit, which helps the user to modify the website name, username and password, the modified password when clicked saved button, replaces the old existing password and uses the same encryption technique before being stored in the database, the delete option deletes the entry and the copy button copies the password to the clip board.

**Random Password Generator**
The random password generator helps the user by generating random password for specified length, for this project 12 character is default. Using the python library secrets the generator randomly selects the characters for the specified length and then the select characters are concatenated to form the final password string. The generated passwords include the uppercase letters, digits and special characters. The function for the random password generator combines all the characters to form a pool of characters from which the random password will be composed to enhance the complexity and security of the password, and when this is stored in the database it is also encrypted using AES-GCM.


**Reset Password**
If the user forgets their password for the Secure Password Manager Application they can reset the password. When user clicks on forgot password they are taken to a window where they enter the user name and answer the security questions, that they have answered during the signup process, the answers during the signup process are hashed using random salt value, so when the enter the security answer before resetting the password, the entered answer is hashed with the combination of salt value if the initial hash value matches the current hash value calculated then it lets the user to the new password page where they can enter the new password for the associated username and the new password replaces the old passwords in the users.db by following the same hashing(SHA-256) and salting techniques.
