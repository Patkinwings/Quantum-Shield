import os
import secrets
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from threading import Thread
import queue

# Post-quantum cryptography libraries
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QuantumResistantFileEncryptor:
    """Encrypts and decrypts files using post-quantum cryptographic algorithms"""
    
    # Constants for security parameters
    PBKDF2_ITERATIONS = 600000  # High iteration count for password-based KDF
    SALT_SIZE = 32  # 256 bits
    KEY_SIZE = 32   # 256 bits
    NONCE_SIZE = 12 # 96 bits
    
    # Default algorithm selections
    DEFAULT_KEM = "Kyber768"  # NIST selected algorithm
    
    def __init__(self, kem_algorithm=None):
        """Initialize with specified or default post-quantum algorithms"""
        self.kem_algorithm = kem_algorithm or self.DEFAULT_KEM
        
        # Validate algorithm support
        if self.kem_algorithm not in oqs.get_enabled_kem_mechanisms():
            raise ValueError(f"KEM algorithm {self.kem_algorithm} is not available")
            
    def generate_keypair(self, output_dir=".", password=None):
        """Generate a keypair for encryption/decryption"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)
        
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            
            # Save keys securely
            pub_path = output_dir / f"quantum_pk_{self.kem_algorithm}.pub"
            with open(pub_path, 'wb') as f:
                f.write(public_key)
            
            # Get password for secret key encryption
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Derive key from password to encrypt the secret key
            salt = secrets.token_bytes(self.SALT_SIZE)
            key = self._derive_key_from_password(password, salt)
            
            # Encrypt secret key with password-derived key
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            encrypted_sk = aesgcm.encrypt(nonce, secret_key, None)
            
            # Create metadata
            metadata = {
                "algorithm": self.kem_algorithm,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "encrypted_secret_key": base64.b64encode(encrypted_sk).decode('utf-8')
            }
            
            # Save encrypted secret key with metadata
            sk_path = output_dir / f"quantum_sk_{self.kem_algorithm}.key"
            with open(sk_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        return str(pub_path), str(sk_path)
    
    def encrypt_file(self, input_file, public_key_file, output_file=None):
        """Encrypt a file using quantum-resistant encryption"""
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file {input_file} not found")
        
        pk_path = Path(public_key_file)
        if not pk_path.exists():
            raise FileNotFoundError(f"Public key file {public_key_file} not found")
        
        # Default output filename
        if output_file is None:
            output_file = str(input_path) + ".qenc"
        
        # Read the public key
        with open(pk_path, 'rb') as f:
            public_key = f.read()
        
        # Encapsulate a shared secret using the public key
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        
        # Generate salt and derive an encryption key from the shared secret
        salt = secrets.token_bytes(self.SALT_SIZE)
        key = self._derive_key_from_shared_secret(shared_secret, salt)
        
        # Initialize AES-GCM with derived key
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Read and encrypt the file in chunks for memory efficiency
        chunk_size = 4096  # 4KB chunks
        encrypted_chunks = []
        
        with open(input_path, 'rb') as f:
            # Read file metadata to include in associated data
            file_size = os.path.getsize(input_path)
            file_name = os.path.basename(input_path)
            
            # Format associated data that will be authenticated but not encrypted
            associated_data = f"{file_name}|{file_size}".encode('utf-8')
            
            # Process file in chunks
            while chunk := f.read(chunk_size):
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, associated_data)
                encrypted_chunks.append(encrypted_chunk)
        
        # Combine encrypted chunks
        encrypted_data = b''.join(encrypted_chunks)
        
        # Prepare metadata
        metadata = {
            "algorithm": self.kem_algorithm,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "associated_data": base64.b64encode(associated_data).decode('utf-8'),
            "original_filename": file_name,
            "original_size": file_size
        }
        
        # Write the encrypted file with metadata
        with open(output_file, 'wb') as f:
            # Write metadata header (JSON as bytes with size prefix)
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            f.write(len(metadata_bytes).to_bytes(4, byteorder='big'))
            f.write(metadata_bytes)
            
            # Write the encrypted data
            f.write(encrypted_data)
        
        return output_file
    
    def decrypt_file(self, encrypted_file, secret_key_file, password, output_file=None):
        """Decrypt a file using quantum-resistant encryption with optimized processing"""
        import logging
        import ctypes
        import os
        from pathlib import Path
        
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger('decryption')
        
        logger.info(f"Starting decryption of {encrypted_file}")
        
        enc_path = Path(encrypted_file)
        if not enc_path.exists():
            logger.error(f"Encrypted file {encrypted_file} not found")
            raise FileNotFoundError(f"Encrypted file {encrypted_file} not found")
        
        sk_path = Path(secret_key_file)
        if not sk_path.exists():
            logger.error(f"Secret key file {secret_key_file} not found")
            raise FileNotFoundError(f"Secret key file {secret_key_file} not found")
        
        # Read encrypted secret key and metadata
        logger.info("Reading secret key file and metadata")
        try:
            with open(sk_path, 'r') as f:
                key_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read key file: {e}")
            raise ValueError(f"Failed to read key file: {e}")
        
        # Get algorithm from key file
        algorithm = key_data.get("algorithm")
        logger.info(f"Key algorithm: {algorithm}")
        if algorithm != self.kem_algorithm:
            logger.error(f"Algorithm mismatch: key={algorithm}, encryptor={self.kem_algorithm}")
            raise ValueError(f"Key algorithm ({algorithm}) doesn't match encryptor algorithm ({self.kem_algorithm})")
        
        # Decrypt the secret key
        logger.info("Decrypting the secret key")
        try:
            salt = base64.b64decode(key_data.get("salt"))
            nonce = base64.b64decode(key_data.get("nonce"))
            encrypted_sk = base64.b64decode(key_data.get("encrypted_secret_key"))
        except Exception as e:
            logger.error(f"Failed to decode key components: {e}")
            raise ValueError(f"Failed to decode key components: {e}")
        
        # Derive key from password
        logger.info("Deriving key from password")
        try:
            key = self._derive_key_from_password(password, salt)
        except Exception as e:
            logger.error(f"Failed to derive key from password: {e}")
            raise ValueError(f"Failed to derive key from password: {e}")
        
        # Decrypt the secret key
        logger.info("Attempting to decrypt secret key")
        try:
            aesgcm = AESGCM(key)
            secret_key = aesgcm.decrypt(nonce, encrypted_sk, None)
            logger.info(f"Secret key decrypted successfully")
        except Exception as e:
            logger.error(f"Failed to decrypt secret key: {e}")
            raise ValueError(f"Failed to decrypt secret key. Invalid password or corrupted key file.") from e
        
        # Read the encrypted file metadata
        logger.info(f"Reading encrypted file metadata: {enc_path}")
        try:
            with open(enc_path, 'rb') as f:
                # Read metadata header
                metadata_size = int.from_bytes(f.read(4), byteorder='big')
                metadata_bytes = f.read(metadata_size)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                
                # Record the current position where the encrypted data starts
                data_start_pos = 4 + metadata_size
        except Exception as e:
            logger.error(f"Failed to read encrypted file metadata: {e}")
            raise ValueError(f"Failed to read encrypted file metadata: {e}")
        
        # Extract encryption parameters
        logger.info("Extracting encryption parameters")
        try:
            file_algorithm = metadata.get("algorithm")
            if file_algorithm != self.kem_algorithm:
                logger.error(f"Algorithm mismatch: file={file_algorithm}, decryptor={self.kem_algorithm}")
                raise ValueError(f"File algorithm ({file_algorithm}) doesn't match decryptor algorithm ({self.kem_algorithm})")
            
            ciphertext = base64.b64decode(metadata.get("ciphertext"))
            enc_salt = base64.b64decode(metadata.get("salt"))
            enc_nonce = base64.b64decode(metadata.get("nonce"))
            associated_data = base64.b64decode(metadata.get("associated_data"))
            original_filename = metadata.get("original_filename")
            expected_size = int(metadata.get("original_size"))
            
            logger.info(f"Original file: {original_filename}, size: {expected_size} bytes")
        except Exception as e:
            logger.error(f"Failed to extract encryption parameters: {e}")
            raise ValueError(f"Failed to extract encryption parameters: {e}")
        
        # Set output file name if not specified
        if output_file is None:
            output_dir = enc_path.parent
            output_file = output_dir / f"decrypted_{original_filename}"
            logger.info(f"Using default output file: {output_file}")
        
        # Initialize the OQS key encapsulation mechanism
        logger.info(f"Initializing OQS KeyEncapsulation with algorithm {self.kem_algorithm}")
        try:
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                # Generate dummy keypair to initialize internal state
                kem.generate_keypair()
                
                # Convert secret_key from bytes to ctypes array
                c_secret_key = (ctypes.c_ubyte * len(secret_key))()
                for i, b in enumerate(secret_key):
                    c_secret_key[i] = b
                
                # Set the converted key
                if hasattr(kem, 'secret_key'):
                    setattr(kem, 'secret_key', c_secret_key)
                elif hasattr(kem, '_secret_key'):
                    kem._secret_key = c_secret_key
                else:
                    secret_attrs = [attr for attr in dir(kem) if 'secret' in attr.lower() and not callable(getattr(kem, attr))]
                    if secret_attrs:
                        setattr(kem, secret_attrs[0], c_secret_key)
                    else:
                        raise ValueError("Could not find appropriate attribute to set secret key")
                
                # Decapsulate the shared secret
                logger.info("Decapsulating shared secret")
                shared_secret = kem.decap_secret(ciphertext)
        except Exception as e:
            logger.error(f"OQS operation failed: {e}")
            raise ValueError(f"OQS operation failed: {e}")
        
        # Derive the file encryption key
        logger.info("Deriving file encryption key")
        try:
            file_key = self._derive_key_from_shared_secret(shared_secret, enc_salt)
        except Exception as e:
            logger.error(f"Failed to derive file key: {e}")
            raise ValueError(f"Failed to derive file key: {e}")
        
        # Define decryption constants
        chunk_size = 4096  # Original encryption chunk size
        tag_size = 16      # AES-GCM tag size
        enc_chunk_size = chunk_size + tag_size
        
        # OPTIMIZED DECRYPTION
        logger.info(f"Starting optimized decryption")
        
        # Prepare output file
        with open(output_file, 'wb') as f:
            f.truncate(expected_size)
        
        try:
            # Open files for streaming
            with open(enc_path, 'rb') as in_file, open(output_file, 'r+b') as out_file:
                # Position input file at the start of encrypted data
                in_file.seek(data_start_pos)
                
                # Process in batches of 20MB (more efficient, less memory usage)
                batch_chunks = 5000  # ~20MB per batch
                file_aesgcm = AESGCM(file_key)
                
                # Get total file size minus header
                in_file.seek(0, os.SEEK_END)
                total_file_size = in_file.tell() - data_start_pos
                in_file.seek(data_start_pos)
                
                total_chunks = total_file_size // enc_chunk_size
                processed_chunks = 0
                last_progress = 0
                
                logger.info(f"Beginning decryption of {total_chunks} chunks")
                
                # Process file in batches to optimize I/O and reduce overhead
                while processed_chunks < total_chunks:
                    # Determine batch size
                    remaining_chunks = total_chunks - processed_chunks
                    current_batch = min(batch_chunks, remaining_chunks)
                    
                    # Read batch of encrypted chunks
                    enc_batch = in_file.read(current_batch * enc_chunk_size)
                    if not enc_batch:
                        break
                    
                    # Process each chunk in the batch
                    for i in range(0, len(enc_batch), enc_chunk_size):
                        chunk_data = enc_batch[i:i+enc_chunk_size]
                        if len(chunk_data) < enc_chunk_size:
                            # Skip incomplete chunks at the end
                            break
                        
                        try:
                            # Decrypt this chunk
                            dec_chunk = file_aesgcm.decrypt(enc_nonce, chunk_data, associated_data)
                            
                            # Write to correct position in file
                            out_pos = (processed_chunks + (i // enc_chunk_size)) * chunk_size
                            if out_pos + len(dec_chunk) <= expected_size:
                                out_file.seek(out_pos)
                                out_file.write(dec_chunk)
                        except Exception as e:
                            logger.warning(f"Error decrypting chunk: {e}")
                            # Continue with other chunks
                    
                    # Update progress counter
                    processed_chunks += current_batch
                    progress_pct = int(processed_chunks * 100 / total_chunks)
                    
                    # Only log when progress percentage changes significantly
                    if progress_pct >= last_progress + 5:
                        logger.info(f"Progress: {progress_pct}% ({processed_chunks}/{total_chunks} chunks)")
                        last_progress = progress_pct
                
                # Ensure file is exactly the right size
                out_file.truncate(expected_size)
                
            logger.info(f"Decryption complete. File saved to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Decryption failed: {e}")
    
    def _derive_key_from_password(self, password, salt):
        """Derive a key from a password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _derive_key_from_shared_secret(self, shared_secret, salt):
        """Derive a key from the shared secret using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=10000,  # Fewer iterations since shared_secret has high entropy
        )
        return kdf.derive(shared_secret)


class QuantumEncryptorApp:
    """GUI application for quantum-resistant file encryption"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum Shield - Post-Quantum File Encryption")
        self.root.geometry("900x680")
        self.root.minsize(900, 680)
        
        # Set theme and styles
        self._setup_styles()
        
        # Main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # App header with logo (text-based for now)
        self._create_header()
        
        # Initialize the queue for thread communication
        self.queue = queue.Queue()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=15)
        
        # Create tabs
        self.keygen_frame = ttk.Frame(self.notebook, padding="20")
        self.encrypt_frame = ttk.Frame(self.notebook, padding="20")
        self.decrypt_frame = ttk.Frame(self.notebook, padding="20")
        self.about_frame = ttk.Frame(self.notebook, padding="20")
        
        self.notebook.add(self.keygen_frame, text="Generate Keys")
        self.notebook.add(self.encrypt_frame, text="Encrypt File")
        self.notebook.add(self.decrypt_frame, text="Decrypt File")
        self.notebook.add(self.about_frame, text="About")
        
        # Create and populate the different tabs
        self._create_keygen_tab()
        self._create_encrypt_tab()
        self._create_decrypt_tab()
        self._create_about_tab()
        
        # Progress frame
        self.progress_frame = ttk.Frame(root, padding="10")
        self.progress_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        self.progress_bar.pack_forget()  # Hide initially
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.progress_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=5)
        
        # Get available algorithms
        self.algorithms = sorted(oqs.get_enabled_kem_mechanisms())
        
        # Initialize encryptor with default algorithm
        self.encryptor = QuantumResistantFileEncryptor()
        
        # Check queue for messages from worker threads
        self.check_queue()
    
    def _setup_styles(self):
        """Set up custom styles for the application"""
        style = ttk.Style()
        
        # Try to use a more modern theme if available
        try:
            style.theme_use("clam")  # or 'alt', 'vista', etc.
        except tk.TclError:
            pass  # Fall back to default if theme not available
        
        # Configure common elements
        style.configure("TFrame", background="#f5f5f7")
        style.configure("TLabel", background="#f5f5f7", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=5)
        style.configure("TEntry", font=("Segoe UI", 10), padding=5)
        style.configure("TNotebook", background="#f5f5f7", tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", padding=[10, 3], font=("Segoe UI", 10))
        
        # Custom styles
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground="#1a1a2e")
        style.configure("Subheader.TLabel", font=("Segoe UI", 12), foreground="#333344")
        style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"), foreground="#1a1a2e")
        
        # Button styles
        style.configure("Action.TButton", font=("Segoe UI", 11, "bold"), padding=8)
        style.configure("Browse.TButton", padding=4)
        
        # Set background for root and main frame
        self.root.configure(background="#f5f5f7")
    
    def _create_header(self):
        """Create application header"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # App title/logo
        title_label = ttk.Label(header_frame, text="Quantum Shield", style="Header.TLabel")
        title_label.pack(side=tk.LEFT)
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame, text="Post-Quantum Cryptographic Protection", style="Subheader.TLabel")
        subtitle_label.pack(side=tk.LEFT, padx=15)
        
    def _create_keygen_tab(self):
        """Create key generation tab content"""
        # Section heading
        ttk.Label(self.keygen_frame, text="Generate New Key Pair", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 15))
        
        # Algorithm selection
        ttk.Label(self.keygen_frame, text="Select Algorithm:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.keygen_algo_var = tk.StringVar(value="Kyber768")
        self.keygen_algo_combo = ttk.Combobox(self.keygen_frame, textvariable=self.keygen_algo_var, width=40, state="readonly")
        self.keygen_algo_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.keygen_algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_change)
        
        ttk.Label(self.keygen_frame, text="Output Directory:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.keygen_outdir_var = tk.StringVar(value=os.path.abspath("."))
        self.keygen_outdir_entry = ttk.Entry(self.keygen_frame, textvariable=self.keygen_outdir_var, width=50)
        self.keygen_outdir_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.keygen_outdir_button = ttk.Button(self.keygen_frame, text="Browse...", style="Browse.TButton", command=self.browse_output_dir)
        self.keygen_outdir_button.grid(row=2, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Password section
        ttk.Separator(self.keygen_frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15)
        ttk.Label(self.keygen_frame, text="Secret Key Password", style="Title.TLabel").grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        
        # Password
        ttk.Label(self.keygen_frame, text="Password:").grid(row=5, column=0, sticky=tk.W, pady=8)
        self.keygen_password_var = tk.StringVar()
        self.keygen_password_entry = ttk.Entry(self.keygen_frame, textvariable=self.keygen_password_var, show="•", width=50)
        self.keygen_password_entry.grid(row=5, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        
        # Confirm Password
        ttk.Label(self.keygen_frame, text="Confirm Password:").grid(row=6, column=0, sticky=tk.W, pady=8)
        self.keygen_confirm_var = tk.StringVar()
        self.keygen_confirm_entry = ttk.Entry(self.keygen_frame, textvariable=self.keygen_confirm_var, show="•", width=50)
        self.keygen_confirm_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        
        # Password hint
        pw_hint = ttk.Label(self.keygen_frame, text="Choose a strong password to protect your secret key", 
                      foreground="#555555", font=("Segoe UI", 9, "italic"))
        pw_hint.grid(row=7, column=1, sticky=tk.W, padx=5)
        
        # Action button frame (for centering)
        action_frame = ttk.Frame(self.keygen_frame)
        action_frame.grid(row=8, column=0, columnspan=3, pady=20)
        
        # Generate button
        self.keygen_button = ttk.Button(action_frame, text="Generate Keypair", style="Action.TButton", command=self.generate_keys)
        self.keygen_button.pack(pady=5)
        
        # Results frame
        result_frame = ttk.LabelFrame(self.keygen_frame, text="Results")
        result_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=10)
        
        # Results display
        self.keygen_result_text = tk.Text(result_frame, height=5, width=60, wrap=tk.WORD, 
                                    background="#ffffff", borderwidth=0, font=("Segoe UI", 10))
        self.keygen_result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.keygen_result_text.config(state=tk.DISABLED)
        
        # Make column 1 expandable
        self.keygen_frame.columnconfigure(1, weight=1)
    
    def _create_encrypt_tab(self):
        """Create file encryption tab content"""
        # Section heading
        ttk.Label(self.encrypt_frame, text="Encrypt a File", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 15))
        
        # Input file selection
        ttk.Label(self.encrypt_frame, text="Input File:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.encrypt_infile_var = tk.StringVar()
        self.encrypt_infile_entry = ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_infile_var, width=50)
        self.encrypt_infile_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.encrypt_infile_button = ttk.Button(self.encrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_encrypt_input)
        self.encrypt_infile_button.grid(row=1, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Public key selection
        ttk.Label(self.encrypt_frame, text="Public Key:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.encrypt_pubkey_var = tk.StringVar()
        self.encrypt_pubkey_entry = ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_pubkey_var, width=50)
        self.encrypt_pubkey_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.encrypt_pubkey_button = ttk.Button(self.encrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_public_key)
        self.encrypt_pubkey_button.grid(row=2, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Output file selection
        ttk.Label(self.encrypt_frame, text="Output File:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.encrypt_outfile_var = tk.StringVar()
        self.encrypt_outfile_entry = ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_outfile_var, width=50)
        self.encrypt_outfile_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.encrypt_outfile_button = ttk.Button(self.encrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_encrypt_output)
        self.encrypt_outfile_button.grid(row=3, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Algorithm selection
        ttk.Label(self.encrypt_frame, text="Algorithm:").grid(row=4, column=0, sticky=tk.W, pady=8)
        self.encrypt_algo_var = tk.StringVar(value="Kyber768")
        self.encrypt_algo_combo = ttk.Combobox(self.encrypt_frame, textvariable=self.encrypt_algo_var, width=40, state="readonly")
        self.encrypt_algo_combo.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.encrypt_algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_change)
        
        # Hint
        encrypt_hint = ttk.Label(self.encrypt_frame, text="Files will be encrypted using AES-256-GCM with post-quantum key exchange", 
                            foreground="#555555", font=("Segoe UI", 9, "italic"))
        encrypt_hint.grid(row=5, column=1, sticky=tk.W, padx=5, pady=(0, 15))
        
        # Action button frame (for centering)
        encrypt_action_frame = ttk.Frame(self.encrypt_frame)
        encrypt_action_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        # Encrypt button
        self.encrypt_button = ttk.Button(encrypt_action_frame, text="Encrypt File", style="Action.TButton", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)
        
        # Results frame
        encrypt_result_frame = ttk.LabelFrame(self.encrypt_frame, text="Results")
        encrypt_result_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=10)
        
        # Results display
        self.encrypt_result_text = tk.Text(encrypt_result_frame, height=5, width=60, wrap=tk.WORD,
                                    background="#ffffff", borderwidth=0, font=("Segoe UI", 10))
        self.encrypt_result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.encrypt_result_text.config(state=tk.DISABLED)
        
        # Make column 1 expandable
        self.encrypt_frame.columnconfigure(1, weight=1)
        # Make result frame expandable
        self.encrypt_frame.rowconfigure(7, weight=1)
    
    def _create_decrypt_tab(self):
        """Create file decryption tab content"""
        # Section heading
        ttk.Label(self.decrypt_frame, text="Decrypt a File", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 15))
        
        # Encrypted file selection
        ttk.Label(self.decrypt_frame, text="Encrypted File:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.decrypt_infile_var = tk.StringVar()
        self.decrypt_infile_entry = ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_infile_var, width=50)
        self.decrypt_infile_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.decrypt_infile_button = ttk.Button(self.decrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_decrypt_input)
        self.decrypt_infile_button.grid(row=1, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Secret key selection
        ttk.Label(self.decrypt_frame, text="Secret Key:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.decrypt_seckey_var = tk.StringVar()
        self.decrypt_seckey_entry = ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_seckey_var, width=50)
        self.decrypt_seckey_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.decrypt_seckey_button = ttk.Button(self.decrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_secret_key)
        self.decrypt_seckey_button.grid(row=2, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Password
        ttk.Label(self.decrypt_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_password_var, show="•", width=50)
        self.decrypt_password_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        
        # Output file selection
        ttk.Label(self.decrypt_frame, text="Output File:").grid(row=4, column=0, sticky=tk.W, pady=8)
        self.decrypt_outfile_var = tk.StringVar()
        self.decrypt_outfile_entry = ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_outfile_var, width=50)
        self.decrypt_outfile_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.decrypt_outfile_button = ttk.Button(self.decrypt_frame, text="Browse...", style="Browse.TButton", command=self.browse_decrypt_output)
        self.decrypt_outfile_button.grid(row=4, column=2, sticky=tk.W, padx=5, pady=8)
        
        # Algorithm selection
        ttk.Label(self.decrypt_frame, text="Algorithm:").grid(row=5, column=0, sticky=tk.W, pady=8)
        self.decrypt_algo_var = tk.StringVar(value="Kyber768")
        self.decrypt_algo_combo = ttk.Combobox(self.decrypt_frame, textvariable=self.decrypt_algo_var, width=40, state="readonly")
        self.decrypt_algo_combo.grid(row=5, column=1, sticky=(tk.W, tk.E), padx=5, pady=8)
        self.decrypt_algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_change)
        
        # Hint
        decrypt_hint = ttk.Label(self.decrypt_frame, text="The algorithm must match the one used during encryption", 
                            foreground="#555555", font=("Segoe UI", 9, "italic"))
        decrypt_hint.grid(row=6, column=1, sticky=tk.W, padx=5, pady=(0, 15))
        
        # Action button frame (for centering)
        decrypt_action_frame = ttk.Frame(self.decrypt_frame)
        decrypt_action_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        # Decrypt button
        self.decrypt_button = ttk.Button(decrypt_action_frame, text="Decrypt File", style="Action.TButton", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)
        
        # Results frame
        decrypt_result_frame = ttk.LabelFrame(self.decrypt_frame, text="Results")
        decrypt_result_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=10)
        
        # Results display
        self.decrypt_result_text = tk.Text(decrypt_result_frame, height=5, width=60, wrap=tk.WORD,
                                    background="#ffffff", borderwidth=0, font=("Segoe UI", 10))
        self.decrypt_result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.decrypt_result_text.config(state=tk.DISABLED)
        
        # Make column 1 expandable
        self.decrypt_frame.columnconfigure(1, weight=1)
        # Make result frame expandable
        self.decrypt_frame.rowconfigure(8, weight=1)
    
    def _create_about_tab(self):
        """Create about tab content"""
        # Create a canvas with scrollbar for the about content
        about_canvas = tk.Canvas(self.about_frame, background="#f5f5f7", highlightthickness=0)
        about_scrollbar = ttk.Scrollbar(self.about_frame, orient="vertical", command=about_canvas.yview)
        about_scrollable_frame = ttk.Frame(about_canvas)
        
        about_scrollable_frame.bind(
            "<Configure>",
            lambda e: about_canvas.configure(scrollregion=about_canvas.bbox("all"))
        )
        
        about_canvas.create_window((0, 0), window=about_scrollable_frame, anchor="nw")
        about_canvas.configure(yscrollcommand=about_scrollbar.set)
        
        about_canvas.pack(side="left", fill="both", expand=True)
        about_scrollbar.pack(side="right", fill="y")
        
        # About content
        about_title = ttk.Label(about_scrollable_frame, text="Quantum Shield", style="Header.TLabel")
        about_title.pack(anchor="w", pady=(0, 5))
        
        about_subtitle = ttk.Label(about_scrollable_frame, text="Post-Quantum Cryptographic Protection", style="Subheader.TLabel")
        about_subtitle.pack(anchor="w", pady=(0, 15))
        
        about_version = ttk.Label(about_scrollable_frame, text="Version 1.0.0", font=("Segoe UI", 10, "italic"))
        about_version.pack(anchor="w", pady=(0, 20))
        
        about_desc_title = ttk.Label(about_scrollable_frame, text="About This Application", style="Title.TLabel")
        about_desc_title.pack(anchor="w", pady=(0, 10))
        
        about_description = """Quantum Shield provides state-of-the-art protection for your files using post-quantum cryptographic algorithms that are designed to remain secure even against attacks from quantum computers.

    Unlike traditional encryption algorithms like RSA and ECC that will become vulnerable to quantum computing attacks, the algorithms used in this application are specifically designed to resist such attacks."""
        
        about_desc_text = tk.Text(about_scrollable_frame, height=5, width=70, wrap=tk.WORD, 
                            background="#f5f5f7", borderwidth=0, font=("Segoe UI", 10))
        about_desc_text.pack(fill=tk.X, pady=(0, 20))
        about_desc_text.insert(tk.END, about_description)
        about_desc_text.config(state=tk.DISABLED)
        
        # Technology section
        tech_title = ttk.Label(about_scrollable_frame, text="Technologies Used", style="Title.TLabel")
        tech_title.pack(anchor="w", pady=(0, 10))
        
        tech_frame = ttk.Frame(about_scrollable_frame)
        tech_frame.pack(fill=tk.X, pady=(0, 20))
        
        tech_items = [
            ("Key Encapsulation Mechanism (KEM):", "Kyber768 (NIST selected algorithm)"),
            ("Symmetric Encryption:", "AES-GCM 256-bit"),
            ("Key Derivation:", "PBKDF2 with SHA3-256"),
            ("Authentication:", "Integrated with AES-GCM"),
            ("Implementation:", "Open Quantum Safe (OQS) library")
        ]
        
        for i, (tech, desc) in enumerate(tech_items):
            ttk.Label(tech_frame, text=tech, font=("Segoe UI", 10, "bold")).grid(row=i, column=0, sticky=tk.W, pady=3)
            ttk.Label(tech_frame, text=desc).grid(row=i, column=1, sticky=tk.W, padx=15, pady=3)
        
        # How to use section
        usage_title = ttk.Label(about_scrollable_frame, text="How To Use", style="Title.TLabel")
        usage_title.pack(anchor="w", pady=(0, 10))
        
        usage_frame = ttk.Frame(about_scrollable_frame)
        usage_frame.pack(fill=tk.X, pady=(0, 20))
        
        usage_steps = [
            "1. Generate a keypair in the 'Generate Keys' tab. Your public key can be shared, but keep your secret key secure.",
            "2. Encrypt files using your (or someone else's) public key in the 'Encrypt File' tab.",
            "3. Decrypt files using your secret key and password in the 'Decrypt File' tab."
        ]
        
        for i, step in enumerate(usage_steps):
            ttk.Label(usage_frame, text=step, wraplength=600).grid(row=i, column=0, sticky=tk.W, pady=5)
        
        # Security notes
        security_title = ttk.Label(about_scrollable_frame, text="Security Notes", style="Title.TLabel")
        security_title.pack(anchor="w", pady=(0, 10))
        
        security_text = """• Your secret key is protected by your password. Choose a strong password and keep it safe.
    - The encrypted secret key never leaves your device in unencrypted form.
    - All encryption and decryption is performed locally on your device.
    - File contents are protected with AES-256-GCM, a highly secure symmetric encryption algorithm.
    - Original file names are stored in the encrypted file metadata."""
        
        security_text_widget = tk.Text(about_scrollable_frame, height=7, width=70, wrap=tk.WORD, 
                                background="#f5f5f7", borderwidth=0, font=("Segoe UI", 10))
        security_text_widget.pack(fill=tk.X, pady=(0, 20))
        security_text_widget.insert(tk.END, security_text)
        security_text_widget.config(state=tk.DISABLED)
        
        # Footer with copyright
        ttk.Separator(about_scrollable_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        footer_text = "© 2025 Quantum Shield. All rights reserved."
        footer_label = ttk.Label(about_scrollable_frame, text=footer_text, foreground="#555555")
        footer_label.pack(anchor="w", pady=5)
    
    def check_queue(self):
        """Check the queue for messages from worker threads"""
        try:
            while True:
                task = self.queue.get_nowait()
                if task["type"] == "progress":
                    self.status_var.set(task["message"])
                elif task["type"] == "result":
                    self.progress_bar.stop()
                    self.progress_bar.pack_forget()
                    
                    if task["success"]:
                        self.status_var.set("Operation completed successfully.")
                        messagebox.showinfo("Success", task["message"])
                    else:
                        self.status_var.set("Operation failed.")
                        messagebox.showerror("Error", task["message"])
                    
                    # Update the results text
                    result_text = task.get("result_text", None)
                    if result_text:
                        if task["operation"] == "keygen":
                            self.update_result_text(self.keygen_result_text, result_text)
                        elif task["operation"] == "encrypt":
                            self.update_result_text(self.encrypt_result_text, result_text)
                        elif task["operation"] == "decrypt":
                            self.update_result_text(self.decrypt_result_text, result_text)
                    
                    # Enable buttons
                    self.keygen_button.config(state=tk.NORMAL)
                    self.encrypt_button.config(state=tk.NORMAL)
                    self.decrypt_button.config(state=tk.NORMAL)
                
                self.queue.task_done()
        except queue.Empty:
            # Queue is empty, reschedule check
            self.root.after(100, self.check_queue)
    
    def on_algorithm_change(self, event):
        """Handle algorithm selection change"""
        # Update all algorithm combos to match
        algorithm = event.widget.get()
        self.keygen_algo_var.set(algorithm)
        self.encrypt_algo_var.set(algorithm)
        self.decrypt_algo_var.set(algorithm)
        
        # Update encryptor
        self.encryptor = QuantumResistantFileEncryptor(algorithm)
    
    def update_result_text(self, text_widget, content):
        """Update the result text widget with the given content"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, content)
        text_widget.config(state=tk.DISABLED)
    
    def browse_output_dir(self):
        """Browse for key output directory"""
        directory = filedialog.askdirectory(initialdir=self.keygen_outdir_var.get())
        if directory:
            self.keygen_outdir_var.set(directory)
    
    def browse_encrypt_input(self):
        """Browse for input file to encrypt"""
        filename = filedialog.askopenfilename(title="Select File to Encrypt")
        if filename:
            self.encrypt_infile_var.set(filename)
            # Auto-set output filename if empty
            if not self.encrypt_outfile_var.get():
                self.encrypt_outfile_var.set(filename + ".qenc")
    
    def browse_public_key(self):
        """Browse for public key file"""
        filename = filedialog.askopenfilename(title="Select Public Key", 
                                                filetypes=[("Public Key", "*.pub"), ("All Files", "*.*")])
        if filename:
            self.encrypt_pubkey_var.set(filename)
    
    def browse_secret_key(self):
        """Browse for secret key file"""
        filename = filedialog.askopenfilename(title="Select Secret Key", 
                                                filetypes=[("Secret Key", "*.key"), ("All Files", "*.*")])
        if filename:
            self.decrypt_seckey_var.set(filename)
    
    def browse_encrypt_output(self):
        """Browse for encrypt output file"""
        filename = filedialog.asksaveasfilename(title="Save Encrypted File As", 
                                                defaultextension=".qenc",
                                                filetypes=[("Encrypted File", "*.qenc"), ("All Files", "*.*")])
        if filename:
            self.encrypt_outfile_var.set(filename)
    
    def browse_decrypt_input(self):
        """Browse for encrypted file to decrypt"""
        filename = filedialog.askopenfilename(title="Select Encrypted File", 
                                                filetypes=[("Encrypted File", "*.qenc"), ("All Files", "*.*")])
        if filename:
            self.decrypt_infile_var.set(filename)
            # Try to extract original filename for default output
            try:
                with open(filename, 'rb') as f:
                    metadata_size = int.from_bytes(f.read(4), byteorder='big')
                    metadata_bytes = f.read(metadata_size)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    original_filename = metadata.get("original_filename")
                    if original_filename and not self.decrypt_outfile_var.get():
                        output_dir = os.path.dirname(filename)
                        self.decrypt_outfile_var.set(os.path.join(output_dir, f"decrypted_{original_filename}"))
            except:
                # If we can't extract, just ignore
                pass
    
    def browse_decrypt_output(self):
        """Browse for decrypt output file"""
        filename = filedialog.asksaveasfilename(title="Save Decrypted File As", 
                                                filetypes=[("All Files", "*.*")])
        if filename:
            self.decrypt_outfile_var.set(filename)
    
    def populate_algorithm_lists(self):
        """Populate the algorithm combo boxes"""
        algorithms = sorted(oqs.get_enabled_kem_mechanisms())
        self.keygen_algo_combo['values'] = algorithms
        self.encrypt_algo_combo['values'] = algorithms
        self.decrypt_algo_combo['values'] = algorithms
        
        # Set default selections
        default_algo = self.encryptor.DEFAULT_KEM
        self.keygen_algo_var.set(default_algo)
        self.encrypt_algo_var.set(default_algo)
        self.decrypt_algo_var.set(default_algo)
    
    def generate_keys(self):
        """Generate a new keypair"""
        # Validate inputs
        output_dir = self.keygen_outdir_var.get()
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory.")
            return
        
        password = self.keygen_password_var.get()
        confirm = self.keygen_confirm_var.get()
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        # Disable buttons during operation
        self.keygen_button.config(state=tk.DISABLED)
        
        # Start progress bar
        self.progress_bar.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        self.progress_bar.start()
        self.status_var.set("Generating keypair...")
        
        # Run in background thread to keep UI responsive
        Thread(target=self._generate_keys_thread, args=(output_dir, password, self.keygen_algo_var.get())).start()
    
    def _generate_keys_thread(self, output_dir, password, algorithm):
        """Background thread for key generation"""
        try:
            # Create encryptor with selected algorithm
            encryptor = QuantumResistantFileEncryptor(algorithm)
            
            # Generate keys
            pub_path, sec_path = encryptor.generate_keypair(output_dir, password)
            
            # Update queue with results
            self.queue.put({
                "type": "result",
                "operation": "keygen",
                "success": True,
                "message": f"Keypair generated successfully.",
                "result_text": f"Public key: {pub_path}\nSecret key: {sec_path}"
            })
        except Exception as e:
            self.queue.put({
                "type": "result",
                "operation": "keygen",
                "success": False,
                "message": f"Key generation failed: {str(e)}"
            })
    
    def encrypt_file(self):
        """Encrypt a file"""
        # Validate inputs
        input_file = self.encrypt_infile_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        
        public_key = self.encrypt_pubkey_var.get()
        if not public_key or not os.path.exists(public_key):
            messagebox.showerror("Error", "Please select a valid public key file.")
            return
        
        output_file = self.encrypt_outfile_var.get()
        if not output_file:
            output_file = input_file + ".qenc"
            self.encrypt_outfile_var.set(output_file)
        
        # Disable buttons during operation
        self.encrypt_button.config(state=tk.DISABLED)
        
        # Start progress bar
        self.progress_bar.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        self.progress_bar.start()
        self.status_var.set("Encrypting file...")
        
        # Run in background thread to keep UI responsive
        Thread(target=self._encrypt_file_thread, 
                args=(input_file, public_key, output_file, self.encrypt_algo_var.get())).start()
    
    def _encrypt_file_thread(self, input_file, public_key, output_file, algorithm):
        """Background thread for file encryption"""
        try:
            # Create encryptor with selected algorithm
            encryptor = QuantumResistantFileEncryptor(algorithm)
            
            # Encrypt file
            output_path = encryptor.encrypt_file(input_file, public_key, output_file)
            
            # Update queue with results
            self.queue.put({
                "type": "result",
                "operation": "encrypt",
                "success": True,
                "message": f"File encrypted successfully.",
                "result_text": f"Encrypted file saved to: {output_path}"
            })
        except Exception as e:
            self.queue.put({
                "type": "result",
                "operation": "encrypt",
                "success": False,
                "message": f"Encryption failed: {str(e)}"
            })
    
    def decrypt_file(self):
        """Decrypt a file"""
        # Validate inputs
        encrypted_file = self.decrypt_infile_var.get()
        if not encrypted_file or not os.path.exists(encrypted_file):
            messagebox.showerror("Error", "Please select a valid encrypted file.")
            return
        
        secret_key = self.decrypt_seckey_var.get()
        if not secret_key or not os.path.exists(secret_key):
            messagebox.showerror("Error", "Please select a valid secret key file.")
            return
        
        password = self.decrypt_password_var.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        
        output_file = self.decrypt_outfile_var.get()
        
        # Disable button during operation
        self.decrypt_button.config(state=tk.DISABLED)
        
        # Start progress bar
        self.progress_bar.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)
        self.progress_bar.start()
        self.status_var.set("Decrypting file...")
        
        # Run in background thread to keep UI responsive
        Thread(target=self._decrypt_file_thread, 
            args=(encrypted_file, secret_key, password, output_file, self.decrypt_algo_var.get())).start()
        
    def _decrypt_file_thread(self, encrypted_file, secret_key, password, output_file, algorithm):
        """Background thread for file decryption"""
        try:
            # Create encryptor with selected algorithm
            encryptor = QuantumResistantFileEncryptor(algorithm)
            
            # Decrypt file
            output_path = encryptor.decrypt_file(encrypted_file, secret_key, password, output_file)
            
            # Update queue with results
            self.queue.put({
                "type": "result",
                "operation": "decrypt",
                "success": True,
                "message": f"File decrypted successfully.",
                "result_text": f"Decrypted file saved to: {output_path}"
            })
        except Exception as e:
            self.queue.put({
                "type": "result",
                "operation": "decrypt",
                "success": False,
                "message": f"Decryption failed: {str(e)}"
            })


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = QuantumEncryptorApp(root)
    
    # Set application icon (if available)
    try:
        root.iconbitmap("lock_icon.ico")
    except:
        pass
    
    # Populate algorithm lists
    app.populate_algorithm_lists()
    
    # Start the application
    root.mainloop()

# This should NOT be indented inside the main() function
if __name__ == "__main__":
    main()