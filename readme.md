**_AES / AES encryption with Galois Counter Mode (GCM)._**
1. AES is a block cipher encryption and decryption algorithm
2. AES is Symmetric Encryption
3. AES processes block of 128 bits using a secret key of 128, 192, or 256 bits.
4. Data gets divided into 128 bits + 128 bits + 128 bits ...
5. GCM = CTR + Authentication.
6. Don’t use AES Electronic codebook (ECB) Mode
7. AES encryption best practice : Don’t reuse IV with the same key.

1. AES String encryption – (encrypt and decrypt a string)
2. AES Password-based encryption – (The secret key will derive from a given password)
3. AES File encryption. (password-based)

**_AES Encryption Inputs_**
1. IV – 96 bits (12 bytes)
2. AES secret key : 256 bits
3. Authentication tag length (in bits) : 128 bits (16 bytes)

**_IV / Initial Value / Initial Vector / Initialization Value_** 
1. It is random bytes, typically 12 bytes or 16 bytes. 
2. In Java, we can use **SecureRandom** to generate the random IV.

**_AES secret key_**
1. The AES secret key, either AES-128 or AES-256. 
2. In Java, we can use **KeyGenerator** to generate the AES secret key.
 
**_AES encryption and decryption_**
1. The AES-GCM inputs:
    AES Secret key (256 bits)
    IV – 96 bits (12 bytes)
    Length (in bits) of authentication tag – 128 bits (16 bytes)
2. In Java, we use AES/GCM/NoPadding to represent the AES-GCM algorithm. 
3. For the encrypted output, we prefix the 16 bytes IV to the encrypted text (ciphertext), 
because we need the same IV for decryption.    
4. Is this ok if IV is publicly known?
   It is ok for IV to be publicly known, the only secret is the key, keep it private and confidential.
   
**_AES Password-Based encryption and decryption_**
1. For password-based encryption, we can use the Password-Based Cryptography Specification (PKCS), 
defined RFC 8018, to generate a key from a given password.
2. For PKCS inputs:
   Password, you provide this.
   Salt – At least 64 bits (8 bytes) random bytes.
   Iteration Count – Recommend a minimum iteration count of 1,000.
3. What is salt and iteration count?
   The salt produces a broad set of keys for a given password. 
   For example, if the salt is 128 bits, there will be as many as 2^128 keys for each password. 
   Therefore, it increases the difficulty of rainbow attacks. 
   Furthermore, the rainbow table that attackers build for one user’s 
   password became useless for another user.
4. What is iteration count?
   The iteration count increasing the cost of producing keys from a password, 
   therefore increasing difficulty and slow down the speed of attacks.
5. For the encrypted output, we prefix the 12 bytes IV and password salt to the ciphertext, 
    because we need the same IV and password salt (for secret key) for decryption
6. we use Base64 encoder to encode the encrypted text into a string representation, 
    so that we can send the encrypted text or ciphertext in string format (was byte array).
7. Is this ok if password salt is publicly known?
   It is the same with IV, and it is ok for password salt to be publicly known, 
   the only secret is the key, keeping it private and confidential.

If password is not match, Java throws AEADBadTagException: Tag mismatch!

**_AES File encryption and decryption_**



Further Reading
1. NIST – Recommendation for Galois/Counter Mode (GCM)
https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf
2. Don’t use AES Electronic codebook (ECB) Mode
   The AES ECB mode, or AES/ECB/PKCS5Padding (in Java) is not semantically secure. 
   The ECB-encrypted ciphertext can leak information about the plaintext. 
   Here is a discussion about Why shouldn’t I use ECB encryption?
https://crypto.stackexchange.com/questions/20941/why-shouldnt-i-use-ecb-encryption
