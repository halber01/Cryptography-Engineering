## Offline attack on hashed passwords (SHA3-256)
In this task, we will perform an offline attack on hashed passwords using the SHA3-256 hashing algorithm. The goal is to find the original password corresponding to a given hash.

### Steps to perform the attack:
1. **Obtain the hash**: You will be given a SHA3-256 hash of a password.
2. **Create a wordlist**: Generate a list of potential passwords. This can be done using common password lists available online or by creating your own based on common patterns (e.g., "password123", "admin2021", etc.).
3. **Hash the passwords**: For each password in your wordlist, compute its SHA3-256 hash.
4. **Compare hashes**: Compare the computed hash of each password with the given hash. If a match is found, you have successfully cracked the password.