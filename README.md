# 🔐 Secure Chat Application

This is a **peer-to-peer (P2P) encrypted chat application** that allows secure messaging between two users — Alice and Bob — via a central authentication server. The application uses **Diffie-Hellman Key Exchange**, **AES Encryption**, and a secure login mechanism.

![Secure Chat Sequence Diagram](IS_ChatApplication.jpg)

---

## 📌 Features

- 🔒 Secure user login with username and password
- 🔐 Key exchange using Diffie-Hellman (DH)
- 🔁 AES-based end-to-end encrypted messaging
- 🧠 Server facilitates authentication and key relay only
- 🧾 Real-time communication with no plaintext key exchange

---

## 🧪 Flow Overview

1. **Authentication Phase**:
   - Alice and Bob login via the server using their credentials.
   - The server verifies and shares each user's public key with the other.

2. **Key Exchange Phase**:
   - Both Alice and Bob generate a shared secret key using the **Diffie-Hellman** method:
     ```
     K = g^(ab) mod p
     ```
   - Server assists in verifying identities and securely forwarding encrypted key components.

3. **Secure Communication Phase**:
   - Messages are encrypted with AES using the shared key `K`.
   - Only the intended recipient can decrypt the message using the same key.

---

## 🔧 Technologies Used

- Java (Core & Networking)
- Java Cryptography (AES, Diffie-Hellman)
- Socket Programming
- Server-Client architecture

---

## 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/J-Praveenan/Secure-Chat-Application.git
