# PQC-test-digital-sign
This tool provides functionality for digitally signing and verifying documents, leveraging various cryptographic algorithms. It supports handling PDF and XML files, enabling users to generate cryptographic keys, sign documents with digital signatures, and verify the authenticity of signed documents.

## Features

- **Generate Cryptographic Keys**: Create digital signature keys using specified algorithms.
- **Sign Documents**: Digitally sign PDF and XML documents.
- **Verify Signatures**: Check the authenticity of digital signatures in documents.

## Requirements

Ubuntu OS only
- Python 3.x
- PyPDF2 library
- lxml library
- OpenSSL version 3.x
- OQS-provider installation

## Installation

Ensure Python 3.x and the required libraries (PyPDF2, lxml) are installed on your system. OpenSSL should also be installed and configured to support the desired cryptographic algorithms.

## Detailed Functionality

### Generate Keys (`generate-keys`)

This function generates a set of cryptographic keys (private and public) for digital signatures. It allows the selection of a specific cryptographic algorithm and requires the user to name the key, which aids in identifying and using it later for signing documents.

**Usage:**

```
python3 digi_sign.py generate-keys [algorithm] [signature_name]
```

- `[algorithm]`: The cryptographic algorithm to use (e.g., dilithium2).
- `[signature_name]`: A unique name for the signature, which is used to label the generated keys.

This command generates a private key (used for signing), a public key (used for verification), and a certificate. The keys and certificate are saved with the signature name as part of their filenames for easy identification.

### Sign Document (`sign`)

After generating keys, this function is used to sign a document. It creates a digital signature using the private key associated with the provided signature name. The function also embeds the signature into the document, producing a signed version of the original file.

**Usage:**

```
python3 digi_sign.py sign [algorithm] [document_filename] [signature_name]
```

- `[document_filename]`: Path to the document to be signed.
- `[signature_name]`: The signature name used during key generation.

The `sign` function performs the following steps:
1. Generates a digital signature of the document using the private key.
2. Embeds the signature and a timestamp into the document.
3. Outputs the signed document and a separate signature file.

### Verify Signature (`verify`)

This function verifies the authenticity of a signed document. It compares the embedded signature in the document against the original file using the public key associated with the signature name.

**Usage:**

```
python3 digi_sign.py verify [algorithm] [document_filename] [signature_name] [signature_filename]
```

- `[signature_filename]`: Path to the signature file generated during the signing process.

The `verify` function checks whether the signature in the signed document matches the one generated from the original document, ensuring the document's integrity and authenticity.

## Algorithms Supported

The tool supports various cryptographic algorithms, including:

- CRYSTALS-Dilithium (dilithium2, p256_dilithium2, rsa3072_dilithium2, dilithium3, p384_dilithium3, dilithium5, p521_dilithium5)

Ensure your OpenSSL installation supports these algorithms.

## Examples

**Generate Keys:**

```
python3 digi_sign.py generate-keys dilithium2 mySignature
```

**Sign a Document:**

```
python3 digi_sign.py sign dilithium2 transactions.pdf mySignature
```

**Verify a Signature:**

```
python3 digi_sign.py verify dilithium2 transactions.pdf mySignature transactions_mySignature_signature_pdf.sha512
```

## Current
In Sign and verfy on both xml and PDF file still not working as those tools may not support PQC Algorithm
TODO:
1. Find the compatible tools that support  PQC Algorithm for digital signature. 
2. Implement to be recognizable in adobe reader or others PDF reader.
