from scapy.all import ICMP, IP, send
import sys

def caesar_cipher(text, shift):
    result = ""

    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
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

    for char in encrypted_message:
        packet = IP(dst=ip_address)/ICMP()/char
        send(packet)
        print(f"Sent: {char}")

if __name__ == "__main__":
    main()