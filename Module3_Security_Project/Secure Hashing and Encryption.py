
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# File names for digital signature keys
PRIVATE_KEY_FILE = Path("private_key.pem")
PUBLIC_KEY_FILE = Path("public_key.pem")


# 1. SHA-256 HASH FOR TEXT
def sha256_text(text):
    result = hashlib.sha256(text.encode("utf-8"))
    return result.hexdigest()


# 2. SHA-256 HASH FOR FILES
def sha256_file(filename):
    digest = hashlib.sha256()

    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)

    return digest.hexdigest()


# 3. CAESAR CIPHER ENCRYPTION AND DECRYPTION
def caesar_cipher(text, shift, decrypt=False):

    if decrypt:
        shift = -shift

    result = ""

    for character in text:

        if character.isupper():
            result += chr(
                (ord(character) - ord("A") + shift) % 26 + ord("A")
            )

        elif character.islower():
            result += chr(
                (ord(character) - ord("a") + shift) % 26 + ord("a")
            )

        else:
            result += character

    return result


# 4. GENERATE RSA DIGITAL SIGNATURE KEYS
def generate_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    PRIVATE_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    print("RSA keys generated successfully!")


# LOAD PRIVATE KEY
def load_private_key():

    return serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=None
    )


# LOAD PUBLIC KEY
def load_public_key():

    return serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )


# 5. SIGN A MESSAGE
def sign_message(message):

    private_key = load_private_key()

    signature = private_key.sign(
        message.encode("utf-8"),

        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),

        hashes.SHA256()
    )

    Path("signature.bin").write_bytes(signature)

    print("Digital signature created successfully!")


# 6. VERIFY DIGITAL SIGNATURE
def verify_message(message):

    public_key = load_public_key()

    signature = Path("signature.bin").read_bytes()

    try:

        public_key.verify(
            signature,
            message.encode("utf-8"),

            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),

            hashes.SHA256()
        )

        print("Signature is VALID!")

    except InvalidSignature:

        print("Signature is INVALID!")


# MAIN APPLICATION MENU
def main():

    while True:

        print("\n===== SIMPLE SECURITY TOOLKIT =====")
        print("1. Generate SHA-256 hash for text")
        print("2. Generate SHA-256 hash for a file")
        print("3. Encrypt text using Caesar cipher")
        print("4. Decrypt text using Caesar cipher")
        print("5. Generate RSA keys")
        print("6. Sign a message")
        print("7. Verify a digital signature")
        print("0. Exit")

        choice = input("\nChoose an option: ")

        try:

            if choice == "1":

                text = input("Enter text: ")

                print("SHA-256 Hash:", sha256_text(text))


            elif choice == "2":

                filename = input("Enter file path: ")

                print("SHA-256 Hash:", sha256_file(filename))


            elif choice == "3":

                text = input("Enter text: ")
                shift = int(input("Enter shift amount: "))

                print("Encrypted text:",
                      caesar_cipher(text, shift))


            elif choice == "4":

                text = input("Enter encrypted text: ")
                shift = int(input("Enter shift amount: "))

                print("Decrypted text:",
                      caesar_cipher(text, shift, True))


            elif choice == "5":

                generate_keys()


            elif choice == "6":

                message = input("Enter message to sign: ")

                sign_message(message)


            elif choice == "7":

                message = input("Enter message to verify: ")

                verify_message(message)


            elif choice == "0":

                print("Goodbye!")

                break


            else:

                print("Invalid choice. Try again.")


        except (OSError, ValueError) as error:

            print("Error:", error)


if __name__ == "__main__":
    main()
