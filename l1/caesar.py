import os
import sys

def caesar_cipher(text, shift):
    result = ""

    for char in text:
        if char.isalpha():  # Only shift alphabets
            shift_amount = shift % 26  # In case shift is more than 26
            if char.islower():
                result += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            result += char

    return result

def main():
    if len(sys.argv) != 4:
        print("Usage: sudo python3 caesar.py \"crypted message\" IP_ADDRESS ROTATION")
        sys.exit(1)

    message = sys.argv[1]
    ip_address = sys.argv[2]
    rotation = int(sys.argv[3])

    encrypted_message = caesar_cipher(message, rotation)
    print(f"Encrypted Message: {encrypted_message}")

    # You can also use encrypted_message in the ping command if needed
    os.system(f"ping {ip_address} -c 1")

if __name__ == "__main__":
    main()