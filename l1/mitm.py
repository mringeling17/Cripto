from scapy.all import sniff, ICMP

def caesar_decrypt(text, shift):
    decrypted = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted += chr(shifted)
        else:
            decrypted += char
    return decrypted

def hex_to_ascii(hex_string):
    bytes_obj = bytes.fromhex(hex_string)
    return bytes_obj.decode("utf-8", errors='replace')

def caesar_cipher_decode(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = -shift % 26 
            if char.islower():
                result += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            result += char
    return result

def hex_to_string(hex_value):
    return bytes.fromhex(hex_value).decode('utf-8')

def reconstruct_message(icmp_payloads):
    messages = []
    print(icmp_payloads, len(icmp_payloads))
    print("---------------------------")

    for payload in icmp_payloads:
        try:
            decoded_payload = hex_to_string(payload.hex())
            messages.append(decoded_payload)
        except UnicodeDecodeError:
            print(f"Unable to decode payload: {payload.hex()}")
            continue
    return ''.join(messages)

def try_all_shifts(encrypted_text):
    decoded_messages = {}
    for shift in range(1, 26):  # Trying all possible shifts
        decoded_message = caesar_cipher_decode(encrypted_text, shift)
        decoded_messages[shift] = decoded_message
        print(f"{shift}:   {decoded_message}")
    return decoded_messages

def process_packet(packet, icmp_payloads):
    if ICMP in packet:
        icmp_payload = packet[ICMP].load  # Extract the ICMP payload
        icmp_payloads.append(icmp_payload)
        print(f"Captured ICMP payload: {icmp_payload.hex()}")  # Log the captured payload

def sniff_icmp_packets(duration=30, count=33):
    print(f"Sniffing started for {duration} seconds or {count} packets...")
    icmp_payloads = []

    try:
        if count is not None:
            sniff(filter="icmp and icmp[icmptype] == icmp-echo", timeout=duration, count=count, prn=lambda packet: process_packet(packet, icmp_payloads), store=False)
        else:
            sniff(filter="icmp and icmp[icmptype] == icmp-echo", timeout=duration, prn=lambda packet: process_packet(packet, icmp_payloads), store=False)
    except Exception as e:
        print(f"Error during sniffing: {e}")

    return icmp_payloads




def main():
    print('Sniffing started')
    icmp_payloads = sniff_icmp_packets(duration=30)

    print(icmp_payloads)
    encrypted_message = reconstruct_message(icmp_payloads)
    print(f"Encrypted Message: {encrypted_message}")

    try_all_shifts(encrypted_message)
 

if __name__ == "__main__":
    main()