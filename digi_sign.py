from PDFNetPython3.PDFNetPython import PDFNet, PDFDoc, SDFDoc, DigitalSignatureField, SignatureWidget, Image, Rect, Field, VerificationOptions, TimestampingConfiguration
import sys
import subprocess
from signxml import XMLSigner, XMLVerifier, methods
from lxml import etree

PDFNet.Initialize("demo:1700755433656:7caccb540300000000aee877819aaa93edceda0f5d7086bc85f2fe302c")

# Function to Run Shell Command
def run_shell_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{' '.join(command)}': {e.stderr}")
        sys.exit(1)

# Function to Get Certificate Subject from User Input
def get_certificate_subject():
    country = input("Country Name (2 letter code): ")
    state = input("State or Province Name: ")
    locality = input("Locality Name: ")
    organization = input("Organization Name: ")
    organizational_unit = input("Organizational Unit Name: ")
    common_name = input("Common Name: ")
    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}"
    return subject

# Function to Generate Keys using OpenSSL
def generate_keys(algorithm, signature_name):
    key_file = f'{signature_name}_key.pem'
    cert_file = f'{signature_name}_cert.pem'
    pubkey_file = f'{signature_name}_key_pubkey.pem'
    run_shell_command(['openssl', 'genpkey', '-algorithm', algorithm, '-outform', 'PEM' ,'-out', key_file])
    subject = get_certificate_subject()
    run_shell_command(['openssl', 'req', '-new', '-x509', '-key', key_file, '-out', cert_file, '-days', '365', '-subj', subject])
    run_shell_command(['openssl', 'pkey', '-in', key_file, '-pubout', '-out', pubkey_file])
    print(f"Key and certificate generated for {signature_name}.")

# Function to generate a PKCS12 file
def generate_pkcs12(signature_name):
    key_file = f'{signature_name}_key.pem'
    cert_file = f'{signature_name}_cert.pem'
    p12_file = f'{signature_name}.p12'
    run_shell_command(['openssl', 'pkcs12', '-export', '-out', p12_file, '-inkey', key_file, '-in', cert_file])
    print(f"PKCS12 file generated for {signature_name}.")

# Function to Generate Digital Signature for PDF
def sign_pdf_with_certificate(pdf_path, signature_name, output_pdf_path, signature_image_path, p12_file_path, p12_password):
    try:
        PDFNet.Initialize()
        doc = PDFDoc(pdf_path)
        doc.InitSecurityHandler()

        # Work with the first page only
        page1 = doc.GetPage(1)
        if page1 is None:
            raise Exception("Page 1 not found in the document.")

        # Calculate position for the signature at the bottom right
        page_width, page_height = page1.GetPageWidth(), page1.GetPageHeight()
        signature_width, signature_height = 100, 50  # Set signature size
        x_coordinate = page_width - signature_width - 10  # 10 units from the right edge
        y_coordinate = 10  # 10 units from the bottom edge
        
        # Create signature field
        sigField = SignatureWidget.Create(doc, Rect(x_coordinate, y_coordinate, x_coordinate + signature_width, y_coordinate + signature_height), signature_name)
        page1.AnnotPushBack(sigField)
        
        # Ensure the field is added to the document's field dictionary
        if not doc.GetField(signature_name):
            doc.FieldCreate(signature_name, Field.e_signature, sigField.GetSDFObj())
        # Prepare the signature field
        approval_field = doc.GetField(signature_name)
        if not approval_field:
            raise Exception("Failed to create digital signature field.")
        approval_signature_digsig_field = DigitalSignatureField(approval_field)
        
        # Add appearance to the signature field
        img = Image.Create(doc.GetSDFDoc(), signature_image_path)
        found_approval_signature_widget = SignatureWidget(approval_field.GetSDFObj())
        found_approval_signature_widget.CreateSignatureAppearance(img)
        # Prepare the signature and signature handler for signing with PKCS#12 file
        # timestamping_config = TimestampingConfiguration("https://freetsa.org/tsr")
        # timestamp_response_verification_options = VerificationOptions()
        # approval_signature_digsig_field.TimestampOnNextSave(timestamping_config, timestamp_response_verification_options)
        approval_signature_digsig_field.SignOnNextSave(p12_file_path, p12_password)
        print("Prepare the signature and signature handler for signing with PKCS#12 file")
        
        # Save the document
        doc.Save(output_pdf_path, SDFDoc.e_incremental)
        print(f"PDF signed and saved as {output_pdf_path}")
    except Exception as e:
        print(f"Error during PDF signing: {e}")


# Function to Sign PDF
def sign_pdf(pdf_path, signature_name, output_pdf_path, signature_image_path, p12_password):
    p12_file_path = f'{signature_name}.p12'
    sign_pdf_with_certificate(pdf_path, signature_name, output_pdf_path, signature_image_path, p12_file_path, p12_password)

# Function to Sign XML with pyasice
def sign_xml_with_pyasice(xml_path, key_file, cert_file, output_xml_path):
    try:
        signer = XMLSigner(key_file=key_file, cert_file=cert_file)
        with open(xml_path, 'rb') as xml_file:
            signed_xml = signer.sign(xml_file)
        with open(output_xml_path, 'wb') as output_file:
            output_file.write(signed_xml)
    except Exception as e:
        print(f"Error signing XML: {e}")
# Function to Sign XML with custom key and certificate
def sign_xml_custom(xml_path, key_file_path, cert_file_path, signature_algorithm ,output_xml_path):
    try:
        with open(xml_path, 'rb') as f:
            xml_data = f.read()

        with open(key_file_path, 'rb') as f:
            key = f.read()

        with open(cert_file_path, 'rb') as f:
            cert = f.read()

        root = etree.fromstring(xml_data)
        signer = XMLSigner(method=methods.enveloped, signature_algorithm=signature_algorithm)
        signed_root = signer.sign(root, key=key, cert=cert)

        with open(output_xml_path, 'wb') as f:
            f.write(etree.tostring(signed_root))
        print("XML signed successfully.")

    except Exception as e:
        print(f"Error signing XML: {e}")

# Function to Verify Signed XML
def verify_signed_xml(signed_xml_path, cert_file_path):
    try:
        with open(signed_xml_path, 'rb') as f:
            signed_xml_data = f.read()

        with open(cert_file_path, 'rb') as f:
            cert = f.read()

        root = etree.fromstring(signed_xml_data)
        verified_data = XMLVerifier().verify(root, x509_cert=cert).signed_xml

        print("XML signature is valid.")
    except Exception as e:
        print(f"Error during XML signature verification: {e}")

# Update the process_file function for XML signing and verifying
def process_file(action, file_type, file_path, signature_name, signature_algorithm, signature_image_path=None, p12_password=None):
    if file_type == 'pdf':
        if action == 'sign':
            output_pdf_path = f'{signature_name}_signed.pdf'
            sign_pdf(file_path, signature_name, output_pdf_path, signature_image_path,p12_password)

        elif action == 'verify':
            pass
    elif file_type == 'xml':
        if action == 'sign':
            output_xml_path = f'{signature_name}_signed.xml'
            sign_xml_custom(file_path, f'{signature_name}_key.pem', f'{signature_name}_cert.pem', signature_algorithm, output_xml_path)
        elif action == 'verify':
            verify_signed_xml(file_path, f'{signature_name}_cert.pem')
    else:
        print("Unsupported file type")

def print_help_message():
    help_message = """
Usage: python digi_sign.py <action> <additional_arguments>

Actions:
  generate-keys - Generate a key and certificate for digital signatures.
    Usage: generate-keys <algorithm> <signature_name>

  sign - Sign a document (PDF or XML).
    Usage: sign <file_type> <file_path> <signature_name>

  verify - Verify a signed document (PDF or XML).
    Usage: verify <file_type> <file_path> <signature_name>

Algorithm for PQC digital signature: 
    CRYSTALS-Dilithium: dilithium2, p256_dilithium2, rsa3072_dilithium2,
    dilithium3, p384_dilithium3, dilithium5, p521_dilithium5

Examples:
  python3 digi_sign.py generate-keys dilithium2 mySignature
  python3 digi_sign.py sign pdf example.pdf mySignature dilithium2 signature_image.jpg your-p12-signature_passwd
  python3 digi_sign.py verify pdf signed_example.pdf mySignature 
  python3 digi_sign.py sign xml example.xml mySignature dilithium2
  python3 digi_sign.py verify xml signed_example.xml mySignature
"""
    print(help_message)

# Main Function for Command-Line Execution
def main():
    if len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        print_help_message()
        return
    if len(sys.argv) < 2:
        print("Incorrect usage. See help for more information.")
        sys.exit(1)
    action = sys.argv[1]
    if action == 'generate-keys':
        if len(sys.argv) != 4:
            print("Incorrect usage for generate-keys. See help for more information.")
            sys.exit(1)
        algorithm = sys.argv[2]
        signature_name = sys.argv[3]
        generate_keys(algorithm, signature_name)
        generate_pkcs12(signature_name)
    elif action == 'sign':
        if len(sys.argv) < 6:
            print("Incorrect usage for sign. See help for more information.")
            sys.exit(1)
        file_type = sys.argv[2]
        file_path = sys.argv[3]
        signature_name = sys.argv[4]
        signature_algorithm = sys.argv[5]
        signature_image_path = sys.argv[6] if len(sys.argv) > 7 and file_type == 'pdf' else None
        p12_password = sys.argv[7] if len(sys.argv) > 7 and file_type == 'pdf' else None
        process_file(action, file_type, file_path, signature_name, signature_algorithm,signature_image_path, p12_password)

    elif action == 'verify':
        if len(sys.argv) != 5:
            print(f"Incorrect usage for {action}. See help for more information.")
            sys.exit(1)
        file_type = sys.argv[2]
        file_path = sys.argv[3]
        signature_name = sys.argv[4]
        process_file(action, file_type, file_path, signature_name)
    else:
        print("Invalid action. Use 'generate-keys', 'sign', or 'verify'.")

if __name__ == "__main__":
    main()
