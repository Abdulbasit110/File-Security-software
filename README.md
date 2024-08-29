# File-Security-Software

This repository contains a Python-based file security software that provides encryption and decryption functionalities using multiple algorithms, such as AES, RSA, and basic encryption methods. It allows users to securely encrypt files and then decrypt them using the corresponding keys.

## Overview

The software is designed to handle various encryption and decryption operations on files, providing flexibility in choosing the encryption method based on the level of security required. The repository contains several example files demonstrating the encryption and decryption processes using different algorithms.

## Features

- **AES Encryption/Decryption**: Secure file encryption using the AES (Advanced Encryption Standard) algorithm.
- **RSA Encryption/Decryption**: Public-key encryption and decryption using the RSA algorithm.
- **Basic Encryption/Decryption**: Simple encryption method for lower-level security requirements.
- **Private/Public Key Management**: Handling private and public keys for RSA encryption.

## Project Structure

```
.
├── encrypted_aes_FE.txt                   // Example file encrypted with AES
├── decrypted_aes_encrypted_aes_FE.txt     // Example file decrypted from AES encryption
├── encrypted_rsa_FE.txt                   // Example file encrypted with RSA
├── decrypted_rsa_encrypted_rsa_FE.txt     // Example file decrypted from RSA encryption
├── encrypted_basic_FE.txt                 // Example file encrypted with basic method
├── decrypted_basic_encrypted_basic_FE.txt // Example file decrypted from basic encryption
├── original code file.py                  // Python script containing the encryption/decryption logic
├── private.pem                            // Private key for RSA encryption
├── recipient.pem                          // Public key for RSA encryption
└── README.md                              // Project README file
```

## Setup Instructions

### Prerequisites

- Python 3.x
- Required Python libraries (e.g., `cryptography`)

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Abdulbasit110/File-Security-software.git
    cd File-Security-software
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Usage

1. To encrypt a file using AES:
    ```bash
    python original_code_file.py --encrypt --method aes --input your_file.txt
    ```

2. To decrypt a file encrypted with AES:
    ```bash
    python original_code_file.py --decrypt --method aes --input encrypted_aes_FE.txt
    ```

3. Similarly, you can use the RSA and basic methods by replacing `--method aes` with `--method rsa` or `--method basic`.

### Learnings

During this project, the following were achieved:

1. **Python Cryptography**: Gained experience in using Python libraries for encryption and decryption.
2. **RSA and AES**: Developed a deeper understanding of RSA and AES encryption algorithms.
3. **File Handling**: Learned how to efficiently handle file I/O operations in Python.
4. **Key Management**: Understood the importance of secure key management in cryptographic systems.

## Contributing

Contributions are welcome! Please create a pull request or open an issue to discuss any changes.
