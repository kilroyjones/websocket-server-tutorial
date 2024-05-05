
import hashlib
import base64

def sha1_and_base64_encode(input_string):
    # Calculate SHA-1 hash of the input string
    sha1_hash = hashlib.sha1(input_string.encode('utf-8')).digest()
    print('SHA', sha1_hash)
    decimal_values = [byte for byte in sha1_hash]
    print(decimal_values)

    hex_string = "c033d81cc3bdb01a1db0fb651c766fc45a1008ef"
    decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    print(decimal_values)


    
    # Base64 encode the SHA-1 hash
    base64_encoded = base64.b64encode(sha1_hash).decode('utf-8')
    
    return base64_encoded

if __name__ == "__main__":
    # Example usage
    # input_string = "Lw2Ccsb2uAbVWPEF7IqhtA==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    # input_string ="oirmnFeh39Bd2HNi9CmewQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    input_string="GDN8ER3kHvtKUji+V25xZA==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    result = sha1_and_base64_encode(input_string)
    print("Original String:", input_string)
    print("SHA-1 + Base64 Encoded String:", result)