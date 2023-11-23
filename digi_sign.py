import sys
import subprocess
import os
from PyPDF2 import PdfReader, PdfWriter, generic
import lxml.etree as ET

def run_shell_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{' '.join(command)}': {e.stderr}")
        sys.exit(1)

def get_certificate_subject():
    country = input("Country Name (2 letter code): ")
    state = input("State or Province Name: ")
    locality = input("Locality Name: ")
    organization = input("Organization Name: ")
    organizational_unit = input("Organizational Unit Name: ")
    common_name = input("Common Name: ")

    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}"
    return subject

def generate_keys(algorithm, signature_name):
    key_file = f'{signature_name}_key.pem'
    cert_file = f'{signature_name}_cert.pem'
    pubkey_file = f'{signature_name}_key_pubkey.pem'

    # Generate key and certificate
    run_shell_command(['openssl', 'genpkey', '-algorithm', algorithm, '-out', key_file])
    subject = get_certificate_subject()
    run_shell_command(['openssl', 'req', '-new', '-x509', '-key', key_file, '-out', cert_file, '-days', '365', '-subj', subject])
    run_shell_command(['openssl', 'pkey', '-in', key_file, '-pubout', '-out', pubkey_file])

    print(f"Key and certificate generated for {signature_name}.")

def sign_document(document_filename, signature_name, algorithm):
    base_filename = os.path.splitext(document_filename)[0]
    file_extension = os.path.splitext(document_filename)[1][1:]  # Extract file extension from document_filename
    key_file = f'{signature_name}_key.pem'
    signature_file = f'{base_filename}_{signature_name}_signature_{file_extension}.sha512'  # Updated naming convention
    tsq_file = f'{base_filename}_{signature_name}.tsq'
    tsr_file = f'{base_filename}_{signature_name}.tsr'

    # Sign the document
    run_shell_command(['openssl', 'dgst', '-sha512', '-sign', key_file, '-out', signature_file, document_filename])
    run_shell_command(['openssl', 'ts', '-query', '-data', signature_file, '-no_nonce', '-sha512', '-out', tsq_file])
    run_shell_command(['curl', '-H', 'Content-Type: application/timestamp-query', '--data-binary', f'@{tsq_file}', 'https://freetsa.org/tsr', '-o', tsr_file])

    print(f"Document {document_filename} signed using {signature_name} with algorithm {algorithm}.")


def verify_signature_with_openssl(algorithm, document_file, signature_name, signature_file):
    public_key_file = f'{signature_name}'+'_key_pubkey.pem'
    result = run_shell_command(['openssl', 'dgst', '-sha512', '-verify', public_key_file, '-signature', signature_file, document_file])
    print(result)

def embed_signature_timestamp_pdf(pdf_path, signature_path, timestamp_path, output_pdf_path):
    try:
        print("Embedding in PDF...")
        with open(pdf_path, 'rb') as file:
            reader = PdfReader(file)
            writer = PdfWriter()

            # Copy pages
            for page in reader.pages:
                writer.add_page(page)

            # Read existing metadata or create new
            existing_metadata = reader.metadata or {}
            signature_count = int(existing_metadata.get("/SignatureCount", 0)) + 1

            # Read signature and timestamp
            with open(signature_path, 'rb') as sig_file, open(timestamp_path, 'rb') as ts_file:
                signature_content = sig_file.read()
                timestamp_content = ts_file.read()

                # Create PdfObject for metadata
                signature_key = generic.create_string_object(f"/Signature{signature_count}")
                timestamp_key = generic.create_string_object(f"/Timestamp{signature_count}")
                existing_metadata[signature_key] = generic.create_string_object(signature_content.hex())
                existing_metadata[timestamp_key] = generic.create_string_object(timestamp_content.hex())
                existing_metadata[generic.create_string_object("/SignatureCount")] = generic.create_string_object(str(signature_count))

            writer.add_metadata(existing_metadata)

            # Write output PDF
            with open(output_pdf_path, 'wb') as output_file:
                writer.write(output_file)

        print("PDF embedding completed.")
    except Exception as e:
        print(f"An error occurred while embedding in PDF: {e}")

# Function to Display All Signatures in PDF
def display_signatures_timestamps_pdf(pdf_path):
    try:
        with open(pdf_path, 'rb') as file:
            reader = PdfReader(file)
            metadata = reader.metadata
            signature_count = int(metadata.get("/SignatureCount", 0))

            for i in range(1, signature_count + 1):
                signature = metadata.get(f"/Signature{i}")
                timestamp = metadata.get(f"/Timestamp{i}")
                print(f"Signature {i}: {signature}")
                print(f"Timestamp {i}: {timestamp}")
    except Exception as e:
        print(f"An error occurred while reading signatures: {e}")

def embed_signature_timestamp_xml(xml_path, signature_path, timestamp_path, output_xml_path):
    try:
        print("Embedding in XML...")
        tree = ET.parse(xml_path)
        root = tree.getroot()

        signatures = root.find(".//Signatures")
        if signatures is None:
            signatures = ET.SubElement(root, "Signatures")

        signature_id = len(signatures) + 1

        with open(signature_path, 'rb') as sig_file, open(timestamp_path, 'rb') as ts_file:
            signature_content = sig_file.read()
            timestamp_content = ts_file.read()

            signature_element = ET.SubElement(signatures, f"Signature{signature_id}")
            signature_element.text = ET.CDATA(signature_content.hex())

            timestamp_element = ET.SubElement(signature_element, "Timestamp")
            timestamp_element.text = ET.CDATA(timestamp_content.hex())

        tree.write(output_xml_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")

        print("XML embedding completed.")
    except Exception as e:
        print(f"An error occurred while embedding in XML: {e}")
        
# Function to Display All Signatures in XML
def display_signatures_timestamps_xml(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        signatures = root.find(".//Signatures")

        if signatures is None:
            print("No signatures found.")
            return

        for i, signature in enumerate(signatures, start=1):
            signature_content = signature.text
            timestamp = signature.find("Timestamp").text
            print(f"Signature {i}: {signature_content}")
            print(f"Timestamp {i}: {timestamp}")
    except Exception as e:
        print(f"An error occurred while reading signatures: {e}")

def embed_signature_timestamp(file_path, signature_path, timestamp_path, output_path):
    if file_path.lower().endswith('.pdf'):
        embed_signature_timestamp_pdf(file_path, signature_path, timestamp_path, output_path)
        display_signatures_timestamps_pdf(output_path)
    elif file_path.lower().endswith('.xml'):
        embed_signature_timestamp_xml(file_path, signature_path, timestamp_path, output_path)
        display_signatures_timestamps_xml(output_path)
    else:
        print("Unsupported file type")

def print_help_message():
    print("Usage: python digi_sign_v5.py <function> <algorithm> <document_filename> [<signature_name>]")
    print("\nFunctions:")
    print("  'generate-keys' - Generates a key and certificate for a signature name.")
    print("    - Usage: python digi_sign_v5.py generate-keys <algorithm> <signature_name>")
    print("  'sign' - Signs a document using the specified signature name.")
    print("    - Usage: python digi_sign_v5.py sign <algorithm> <document_filename> <signature_name>")
    print("  'verify' - Verifies the signature of the specified document.")
    print("    - Usage: python digi_sign_v5.py verify <algorithm> <document_filename> <signature_filename>")
    print("\nAlgorithm for digital signature: ")
    print(" CRYSTALS-Dilithium: dilithium2, p256_dilithium2, rsa3072_dilithium2, dilithium3, p384_dilithium3, dilithium5, p521_dilithium5")
    print("\nExamples:")
    print("  python3 digi_sign_v5.py generate-keys dilithium2 mySignature1")
    print("  python3 digi_sign_v5.py sign dilithium2 transactions.pdf mySignature1")
    print("  python3 digi_sign_v5.py verify dilithium2 transactions.pdf mySignature1 transactions_mySignature1_signature_pdf.sha512")

def main():
    if len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        print_help_message()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Missing arguments. For usage instructions, run:")
        print("  python digi_sign_v5.py --help")
        sys.exit(1)

    function = sys.argv[1]
    algorithm = sys.argv[2]

    if function == 'generate-keys':
        if len(sys.argv) < 4:
            print("Missing signature name. Usage: python digi_sign_v5.py generate-keys <algorithm> <signature_name>")
            sys.exit(1)
        signature_name = sys.argv[3]
        generate_keys(algorithm, signature_name)
    elif function == 'sign':
        if len(sys.argv) < 5:
            print("Missing arguments. Usage: python digi_sign_v5.py sign <algorithm> <document_filename> <signature_name>")
            sys.exit(1)
        document_filename = sys.argv[3]
        signature_name = sys.argv[4]
        sign_document(document_filename, signature_name, algorithm)
        base_filename = os.path.splitext(document_filename)[0]
        file_extension = os.path.splitext(document_filename)[1][1:]  # Extract file extension from document_filename
        signature_file = f'{base_filename}_{signature_name}_signature_{file_extension}.sha512'  # Updated naming convention
        tsr_file = f'{base_filename}_{signature_name}.tsr'
        output_file = f'{base_filename}_{signature_name}_signed.{document_filename.split(".")[-1]}'
        embed_signature_timestamp(document_filename, signature_file, tsr_file, output_file)
        print(f"Embedding completed. Signed document: {output_file}")
    elif function == 'verify':
        if len(sys.argv) < 6:
            print("Missing arguments. Usage: python digi_sign_v5.py verify <algorithm> <document_filename> <signature_name> <signature_filename>")
            sys.exit(1)
        document_filename = sys.argv[3]
        signature_name = sys.argv[4]
        signature_filename = sys.argv[5]
        verify_signature_with_openssl(algorithm, document_filename, signature_name,  signature_filename)
    else:
        print("Invalid function type or missing arguments. Use 'generate-keys', 'sign', or 'verify'.")

if __name__ == "__main__":
    main()
