import oqs
import base64
import json
from pathlib import Path

# Function to test key decapsulation
def test_decapsulation(secret_key_file, password):
    # Read the secret key file
    with open(secret_key_file, 'r') as f:
        key_data = json.load(f)
    
    # Print key structure information
    print(f"Key file structure: {list(key_data.keys())}")
    print(f"Algorithm: {key_data.get('algorithm')}")
    
    # Dummy ciphertext for testing
    algorithm = key_data.get("algorithm")
    
    # Generate a test keypair
    print("Generating test keypair...")
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        test_secret_key = kem.export_secret_key()
        test_ciphertext, shared_secret = kem.encap_secret(public_key)
    
    # Print secret key info
    print(f"Test secret key type: {type(test_secret_key)}")
    print(f"Test secret key length: {len(test_secret_key)}")
    print(f"First few bytes: {test_secret_key[:10]}")
    
    # Try different methods to use the secret key
    print("\nTrying different approaches to use secret key...")
    
    # Approach 1: Try using a new instance with original test keys
    try:
        print("\nApproach 1: Using fresh test keys")
        with oqs.KeyEncapsulation(algorithm) as kem:
            kem.generate_keypair()  # Generate dummy keypair
            # Print available attributes related to secret key
            secret_attrs = [attr for attr in dir(kem) if 'secret' in attr.lower()]
            print(f"Attributes related to secret key: {secret_attrs}")
            
            if hasattr(kem, '_secret_key'):
                print("Setting _secret_key directly")
                kem._secret_key = test_secret_key
            
            # Try decapsulation
            result = kem.decap_secret(test_ciphertext)
            print("Decapsulation successful!")
    except Exception as e:
        print(f"Approach 1 failed: {e}")
    
    # Print OQS library version info if available
    try:
        if hasattr(oqs, 'version'):
            print(f"\nOQS library version: {oqs.version()}")
        elif hasattr(oqs, '__version__'):
            print(f"\nOQS library version: {oqs.__version__}")
    except Exception as e:
        print(f"Could not get OQS version: {e}")
    
    print("\nTest complete")

# Run the test with your secret key file
test_decapsulation("C:/Users/35387/OneDrive/Desktop/testfile/quantum_sk_Kyber768.key", "your_password")