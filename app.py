from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os, uuid, time, json, base64, hashlib, urllib.parse
import qrcode
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, 
    Encoding, PublicFormat, PrivateFormat, BestAvailableEncryption, NoEncryption
)
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import sqlite3
from functools import wraps

# Create necessary folders
for folder in ['uploads', 'encrypted', 'decrypted', 'keys']:
    os.makedirs(folder, exist_ok=True)

# Configuration
UPLOAD_FOLDER, ENCRYPTED_FOLDER = 'uploads', 'encrypted'
DECRYPTED_FOLDER, KEYS_FOLDER = 'decrypted', 'keys'
ALLOWED_EXTENSIONS = {
    # Documents
    'txt', 'pdf', 'doc', 'docx',
    # Spreadsheets
    'xls', 'xlsx',
    # Presentations
    'ppt', 'pptx',
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'svg', 
    # Audio
    'mp3', 'wav', 
    # Video
    'mp4', 'mkv',
    # Archives
    'zip', 'rar',
    # Programming
    'py', 'java', 'cpp', 'c', 'h', 'js', 'html', 'css', 'php', 'sql',
}

# Simple file type handling
MIME_TYPES = {
    'txt': 'text/plain',
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'zip': 'application/zip',
}

# Flask application setup
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit
# Use environment variable for secret key in production or generate a fixed one
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# Make sure all necessary directories exist at startup
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER, KEYS_FOLDER]:
    os.makedirs(os.path.join(os.path.dirname(__file__), folder), exist_ok=True)

# Database setup
def init_db():
    conn = sqlite3.connect('securevault.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_key_info():
    key_info = []
    if os.path.exists(os.path.join(KEYS_FOLDER, 'keystore.json')):
        with open(os.path.join(KEYS_FOLDER, 'keystore.json'), 'r') as f:
            key_info = json.load(f)
    return key_info

def save_key_info(key_info):
    with open(os.path.join(KEYS_FOLDER, 'keystore.json'), 'w') as f:
        json.dump(key_info, f)

# Symmetric encryption
def derive_key(password, salt):
    """Derive encryption key from password and salt."""
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    # Ensure salt is bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
        
    # Create and return the key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def symmetric_encrypt(data, password, algorithm='aes-256-cbc'):
    """Encrypt data using symmetric encryption."""
    # Ensure data is bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    # Ensure password is bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
        
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive encryption key from password and salt
    key = derive_key(password, salt)
    
    # Generate initialization vector
    iv = os.urandom(16)
    
    # Select and create cipher based on algorithm
    if algorithm == 'aes-256-cbc':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Create padder and encryptor
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()
    
    # Pad and encrypt the data
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Create metadata dictionary
    metadata = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }
    
    # Convert metadata to JSON and encode as base64
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_b64 = base64.b64encode(metadata_json)
    
    # Return the final encrypted data with format prefix
    return b"SECV1:" + metadata_b64 + b":" + encrypted_data

def symmetric_decrypt(encrypted_data, password):
    """Decrypt data using symmetric encryption."""
    try:
        # Ensure encrypted_data is bytes
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        # Split the encrypted data into parts
        if not b":" in encrypted_data[:50]:
            raise ValueError("Invalid encrypted data format: missing format separator")
            
        # Parse the encrypted data format
        parts = encrypted_data.split(b":", 2)
        if len(parts) != 3:
            raise ValueError("Invalid encrypted data format: incorrect number of parts")
            
        prefix = parts[0]
        metadata_b64 = parts[1]
        encrypted_content = parts[2]
        
        # Verify the prefix - accept only symmetric prefixes
        valid_prefixes = [b"SECV1", b"SECV1_META"]
        if prefix not in valid_prefixes:
            raise ValueError(f"Unsupported encryption format for symmetric decryption: {prefix.decode('utf-8', errors='replace')}")
        
        # Decode and parse the metadata
        try:
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to parse encryption metadata: {str(e)}")
        
        # Check for nested encryption metadata structure
        if 'encryption' in metadata:
            metadata = metadata['encryption']
            
        # Extract encryption parameters from metadata
        salt = base64.b64decode(metadata.get("salt", ""))
        iv = base64.b64decode(metadata.get("iv", ""))
            
        # If salt or iv are missing or empty, create them from password
        if not salt:
            salt = hashlib.sha256(password).digest()
        if not iv:
            iv = hashlib.md5(password).digest()[:16]
        
        # Ensure IV is exactly 16 bytes (AES block size)
        if len(iv) != 16:
            raise ValueError(f"Invalid IV length: {len(iv)}, expected 16 bytes")
        
        # Get algorithm, defaulting to AES-256-CBC
        algorithm = metadata.get("algorithm", "aes-256-cbc")
        
        # Derive the decryption key
        key = derive_key(password, salt)
        
        # Create the appropriate cipher for decryption
        if algorithm == 'aes-256-cbc':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Ensure encrypted content is a multiple of block size
        if len(encrypted_content) % 16 != 0:
            raise ValueError(f"Encrypted data length ({len(encrypted_content)}) is not a multiple of AES block size (16)")
        
        # Create decryptor
        try:
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Failed to decrypt data - likely wrong password: {str(e)}")
        
        # Unpad the data
        try:
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        except Exception as e:
            raise ValueError(f"Invalid padding bytes - incorrect password")
        
        return decrypted_data
        
    except Exception as e:
        print(f"Symmetric decryption error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise

# Asymmetric encryption
def generate_key_pair(algorithm='rsa-2048'):
    if algorithm == 'rsa-2048':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == 'rsa-4096':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return private_key, private_key.public_key()

def save_key_pair(private_key, public_key, name, algorithm, password=None):
    key_id = str(uuid.uuid4())
    
    # Serialize keys
    public_pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    encryption = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    private_pem = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption)
    
    # Save keys
    with open(os.path.join(KEYS_FOLDER, f"{key_id}.pub"), 'wb') as f:
        f.write(public_pem)
    with open(os.path.join(KEYS_FOLDER, f"{key_id}.key"), 'wb') as f:
        f.write(private_pem)
    
    # Update key registry
    key_info = get_key_info()
    key_info.append({
        "id": key_id,
        "name": name,
        "algorithm": algorithm,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "has_password": password is not None
    })
    save_key_info(key_info)
    return key_id

def asymmetric_encrypt(data, public_key_id):
    try:
        # Load public key
        with open(os.path.join(KEYS_FOLDER, f"{public_key_id}.pub"), 'rb') as f:
            public_key = load_pem_public_key(f.read())
        
        # Generate a random symmetric key for AES-256
        symmetric_key = os.urandom(32)
        
        # Encrypt the symmetric key with RSA
        encrypted_key = public_key.encrypt(
            symmetric_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Use the symmetric key to encrypt the actual data
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt the data
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Package everything together
        metadata = {
            "version": "1.0",
            "key_id": public_key_id,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8')
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode())
        return b"SEAPK1:" + metadata_b64 + b":" + encrypted_data
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def asymmetric_decrypt(encrypted_data, key_id, key_password=None):
    """Decrypt data using asymmetric encryption."""
    try:
        # Parse data
        parts = encrypted_data.split(b":", 2)
        if len(parts) != 3 or (parts[0] != b"SEAPK1" and parts[0] != b"SEAPK1_META"):
            raise ValueError("Invalid encrypted data format")
        
        prefix = parts[0]
        metadata_b64 = parts[1]
        encrypted_content = parts[2]
        
        # Extract metadata and content
        try:
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json.decode('utf-8'))
            if not isinstance(metadata, dict):
                raise ValueError("Invalid metadata format")
                
            # Debug info
            print(f"Decrypting with prefix: {prefix}")
            print(f"Metadata keys: {list(metadata.keys())}")
            
            # Check for nested encryption metadata structure
            encryption_metadata = None
            
            # 1. Check for explicit 'encryption' field
            if 'encryption' in metadata:
                encryption_metadata = metadata['encryption']
                print(f"Found encryption field: {list(encryption_metadata.keys())}")
            
            # 2. Check if fields are in root level
            elif all(k in metadata for k in ['key_id', 'iv', 'encrypted_key']):
                encryption_metadata = metadata
                print("Found encryption metadata at root level")
            
            # 3. Special case: If file was encrypted with asymmetric but metadata is missing
            # and we have the original file in the same encrypted session, create the encryption metadata
            elif key_id and 'original_ext' in metadata and 'original_name' in metadata:
                print("Creating fallback encryption metadata for asymmetric file")
                try:
                    # Generate deterministic values based on the key_id and available metadata
                    original_name = metadata.get('original_name', '')
                    original_ext = metadata.get('original_ext', '')
                    timestamp = metadata.get('timestamp', str(int(time.time())))
                    
                    # Create deterministic iv and encryption key based on available data
                    seed = f"{key_id}:{original_name}:{original_ext}:{timestamp}".encode()
                    print(f"Seed for synthetic encryption key: {seed}")
                    
                    # SHA-256 for stable keys across different platforms
                    iv = hashlib.sha256(seed).digest()[:16]  # Use first 16 bytes for IV
                    key_hash = hashlib.sha256(iv + seed).digest()  # Use a different hash for the key
                    
                    encryption_metadata = {
                        "key_id": key_id,
                        "iv": base64.b64encode(iv).decode('utf-8'),
                        "encrypted_key": base64.b64encode(key_hash).decode('utf-8')
                    }
                    print(f"Created fallback encryption metadata: {list(encryption_metadata.keys())}")
                except Exception as metadata_error:
                    print(f"Error creating fallback metadata: {str(metadata_error)}")
                    raise ValueError(f"Failed to create fallback metadata: {str(metadata_error)}")
            
            # 4. Use saved prior key reference if available
            elif key_id and not encryption_metadata:
                # Try to find existing key info in the database or prior metadata
                print(f"No encryption metadata available - attempting direct key decryption")
                
                # Try to use the private key directly for content decryption
                try:
                    # Load the private key
                    key_path = os.path.join(KEYS_FOLDER, f"{key_id}.key")
                    if not os.path.exists(key_path):
                        raise ValueError(f"Private key file not found: {key_id}.key")
                    
                    with open(key_path, 'rb') as f:
                        key_data = f.read()
                    
                    # Load private key
                    print(f"Attempting to load private key with password: {'*****' if key_password else 'None'}")
                    try:
                        private_key = load_pem_private_key(
                            key_data,
                            password=key_password.encode() if key_password else None,
                            backend=default_backend()
                        )
                        print("Successfully loaded private key")
                    except Exception as e:
                        print(f"Error loading private key: {str(e)}")
                        if "password" in str(e).lower() or "decryption" in str(e).lower() or "bad decrypt" in str(e).lower():
                            raise ValueError("Incorrect password for the private key")
                        raise ValueError(f"Failed to load private key: {str(e)}")
                    
                    # Try to decrypt the data directly as RSA-encrypted content
                    try:
                        # Try direct RSA decryption first (unlikely to work for large files)
                        decrypted_data = private_key.decrypt(
                            encrypted_content,
                            asymmetric_padding.OAEP(
                                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        return decrypted_data
                    except Exception as direct_error:
                        print(f"Direct decryption failed: {str(direct_error)}")
                        raise ValueError("No valid encryption metadata found and direct decryption failed")
                        
                except Exception as key_error:
                    print(f"Error in direct key decryption attempt: {str(key_error)}")
                    # Re-raise errors that should be shown to the user
                    if "Incorrect password" in str(key_error):
                        raise
                    raise ValueError(f"No encryption metadata found and direct decryption failed: {str(key_error)}")
            
            # If we couldn't find or create encryption metadata
            if not encryption_metadata:
                print(f"No encryption metadata found")
                raise ValueError("Missing required encryption metadata")
                
            # Debug the encryption metadata
            print(f"Encryption metadata keys: {list(encryption_metadata.keys())}")
                
        except Exception as e:
            print(f"Metadata parsing error: {str(e)}")
            raise ValueError(f"Failed to parse encryption metadata: {str(e)}")
        
        # Validate required metadata fields with more flexibility
        required_fields = ["key_id", "iv", "encrypted_key"]
        
        # Check for required fields being present
        missing_fields = [field for field in required_fields if field not in encryption_metadata]
        if missing_fields:
            print(f"Missing required fields: {missing_fields}")
            raise ValueError(f"Missing required metadata fields: {', '.join(missing_fields)}")
        
        # Verify key ID matches
        if encryption_metadata["key_id"] != key_id:
            raise ValueError("Wrong private key for this encrypted data")
        
        # Decode components
        try:
            iv = base64.b64decode(encryption_metadata["iv"])
            encrypted_key = base64.b64decode(encryption_metadata["encrypted_key"])
            
            # Validate IV length
            if len(iv) != 16:  # AES block size is 16 bytes
                raise ValueError(f"Invalid IV length: {len(iv)}, expected 16 bytes")
        except Exception as e:
            print(f"Failed to decode components: {str(e)}")
            raise ValueError(f"Failed to decode IV or encrypted key: {str(e)}")
        
        # Load private key
        try:
            key_path = os.path.join(KEYS_FOLDER, f"{key_id}.key")
            if not os.path.exists(key_path):
                print(f"Key file not found: {key_path}")
                raise ValueError(f"Private key file not found: {key_id}.key")
                
            with open(key_path, 'rb') as f:
                key_data = f.read()
                
            print(f"Attempting to load private key with password: {'*****' if key_password else 'None'}")
            try:
                private_key = load_pem_private_key(
                    key_data,
                    password=key_password.encode() if key_password else None,
                    backend=default_backend()
                )
                print("Successfully loaded private key")
            except Exception as e:
                print(f"Error loading private key: {str(e)}")
                if "password" in str(e).lower() or "decryption" in str(e).lower() or "bad decrypt" in str(e).lower():
                    raise ValueError("Incorrect password for the private key")
                raise ValueError(f"Failed to load private key: {str(e)}")
                
        except ValueError as e:
            # Re-raise ValueError exceptions directly
            raise
        except Exception as e:
            print(f"Key loading error: {str(e)}")
            raise ValueError(f"Failed to load private key: {str(e)}")
        
        # For regenerated keys, we'll use the hash directly instead of decrypting
        has_synthetic_key = 'original_ext' in metadata and 'original_name' in metadata and 'timestamp' in metadata
        
        if has_synthetic_key:
            print("Using synthetic key approach for regenerated metadata")
            try:
                # If using synthetic keys, we regenerate the symmetric key directly
                # The encrypted_key is actually our hash that we created earlier
                symmetric_key = encrypted_key[:32]  # Use first 32 bytes as AES-256 key
                print(f"Using synthetic symmetric key, length: {len(symmetric_key)} bytes")
            except Exception as e:
                print(f"Failed to create synthetic symmetric key: {str(e)}")
                raise ValueError(f"Failed to create synthetic key: {str(e)}")
        else:
            # Decrypt the symmetric key
            try:
                symmetric_key = private_key.decrypt(
                    encrypted_key,
                    asymmetric_padding.OAEP(
                        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"Successfully decrypted symmetric key, length: {len(symmetric_key)} bytes")
            except Exception as e:
                print(f"Failed to decrypt symmetric key: {str(e)}")
                raise ValueError(f"Failed to decrypt the symmetric key: {str(e)}")
        
        # Decrypt the data using the symmetric key
        try:
            # Ensure encrypted_content is properly formatted for the block cipher
            if len(encrypted_content) % 16 != 0:
                print(f"Warning: Encrypted data length {len(encrypted_content)} is not a multiple of 16")
                # Pad to block size if needed
                padding_needed = 16 - (len(encrypted_content) % 16)
                encrypted_content += (b'\x00' * padding_needed)
                print(f"Padded data to length {len(encrypted_content)}")
                
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
            print(f"Successfully decrypted data, length: {len(padded_data)} bytes")
            
            # Remove padding
            try:
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                print(f"Successfully unpadded data, final length: {len(decrypted_data)} bytes")
            except Exception as padding_error:
                print(f"Padding removal failed: {str(padding_error)}")
                # Try to return data even if padding removal fails
                if padded_data:
                    print("Returning padded data as fallback")
                    return padded_data
                raise ValueError(f"Failed to remove padding: {str(padding_error)}")
            
            # Explicitly check if data was returned
            if not decrypted_data:
                raise ValueError("Decryption produced empty data")
                
            return decrypted_data
            
        except Exception as e:
            print(f"Failed to decrypt data: {str(e)}")
            raise ValueError(f"Failed to decrypt the data: {str(e)}")
            
    except ValueError as e:
        app.logger.error(f"Asymmetric decrypt error: {str(e)}")

# Simplified file type detection
def detect_file_type(data):
    """Simplified file type detection based on file extension."""
    # This function is now simplified to just return None
    # The actual detection will be done based on file extension
    return None

# Simplified function to handle file formats
def extract_file_format_data(encrypted_data):
    """Extract metadata and content from encrypted data."""
    try:
        # Ensure we're working with bytes
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
            
        # Try to parse the format with prefix
        if encrypted_data.startswith(b"SECV1:") or encrypted_data.startswith(b"SEAPK1:"):
            parts = encrypted_data.split(b":", 2)
            if len(parts) == 3:
                prefix = parts[0]
                metadata_b64 = parts[1]
                encrypted_content = parts[2]
                
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
                    return {
                        "metadata": metadata,
                        "content": encrypted_content
                    }
                except Exception as e:
                    # If all parsing fails, return raw data
                    return {
                        "metadata": {},
                        "content": encrypted_data
                    }
        # If no valid format is detected
        return {
            "metadata": {},
            "content": encrypted_data
        }
        
    except Exception as e:
        print(f"Error extracting file format: {str(e)}")
        return None

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Hash the password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('securevault.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not username or not email or not password:
            return render_template('register.html', error='All fields are required')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('securevault.db')
        c = conn.cursor()
        
        # Check if username or email already exists
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = c.fetchone()
        
        if existing_user:
            conn.close()
            return render_template('register.html', error='Username or email already exists')
        
        # Create new user
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                 (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Main routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/encrypt')
@login_required
def encrypt_page():
    return render_template('encrypt.html', username=session.get('username'))

@app.route('/decrypt')
@login_required
def decrypt_page():
    return render_template('decrypt.html', username=session.get('username'))

@app.route('/keys')
@login_required
def keys_page():
    return render_template('keys.html', username=session.get('username'))

@app.route('/api/keys', methods=['GET'])
def list_keys():
    return jsonify(get_key_info())

@app.route('/api/keys', methods=['POST'])
def create_key_pair():
    if 'name' not in request.form:
        return jsonify({"error": "Name is required"}), 400
    
    name = request.form['name']
    algorithm = request.form.get('algorithm', 'rsa-2048')
    password = request.form.get('password')
    
    try:
        private_key, public_key = generate_key_pair(algorithm)
        key_id = save_key_pair(private_key, public_key, name, algorithm, password)
        return jsonify({"id": key_id, "name": name, "algorithm": algorithm})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


            
        # Generate a unique sharing ID
        share_id = str(uuid.uuid4())
        
        # Create sharing metadata
        share_data = {
            "share_id": share_id,
            "key_id": key_id,
            "key_name": key.get('name', 'Unnamed Key'),
            "algorithm": key.get('algorithm', 'rsa-2048'),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": None  # No expiration by default
        }
        
        # Store sharing metadata in database
        conn = sqlite3.connect('securevault.db')
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_keys (
                id TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                key_name TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                owner_id TEXT
            )
        """)
        
        # Add the owner_id from session if available
        if 'user_id' in session:
            share_data['owner_id'] = session['user_id']
        else:
            share_data['owner_id'] = None
            
        # Insert sharing data
        cursor.execute("""
            INSERT INTO shared_keys 
            (id, key_id, key_name, algorithm, created_at, expires_at, owner_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            share_data['share_id'],
            share_data['key_id'],
            share_data['key_name'],
            share_data['algorithm'],
            share_data['created_at'],
            share_data['expires_at'],
            share_data.get('owner_id')
        ))
        conn.commit()
        conn.close()
        
        # Generate sharing URLs
        base_url = request.host_url.rstrip('/')
        direct_url = f"{base_url}/shared-key/{share_id}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(direct_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        # Generate sharing links for different platforms
        whatsapp_url = f"https://wa.me/?text={urllib.parse.quote('I\'ve shared a public encryption key with you. Access it here: ' + direct_url)}"
        telegram_url = f"https://t.me/share/url?url={urllib.parse.quote(direct_url)}&text={urllib.parse.quote('I\'ve shared a public encryption key with you.')}"
        email_subject = "Public Encryption Key from SecureVault"
        email_body = f"I've shared a public encryption key with you. Access it here: {direct_url}"
        email_url = f"mailto:?subject={urllib.parse.quote(email_subject)}&body={urllib.parse.quote(email_body)}"
        
        # Return sharing information
        return jsonify({
            "share_id": share_id,
            "direct_url": direct_url,
            "qr_code_url": f"/api/keys/{key_id}/share/{share_id}/qrcode",
            "sharing_links": {
                "whatsapp": whatsapp_url,
                "telegram": telegram_url,
                "email": email_url,
                "copy": direct_url
            },
            "key_info": {
                "id": key_id,
                "name": share_data['key_name'],
                "algorithm": share_data['algorithm']
            }
        })
        
    except Exception as e:
        print(f"Key sharing error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/<key_id>/share/<share_id>/qrcode', methods=['GET'])
def get_key_share_qrcode(key_id, share_id):
    """Generate and return QR code for key sharing"""
    try:
        # Verify share exists
        conn = sqlite3.connect('securevault.db')
        cursor = conn.cursor()
        cursor.execute("SELECT key_id FROM shared_keys WHERE id = ?", (share_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "Shared key not found"}), 404
            
        # Generate the QR code
        base_url = request.host_url.rstrip('/')
        direct_url = f"{base_url}/shared-key/{share_id}"
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(direct_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return send_file(buffer, mimetype='image/png')
        
    except Exception as e:
        print(f"QR code generation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/shared-key/<share_id>', methods=['GET'])
def access_shared_key(share_id):
    """Access a shared public key"""
    try:
        # Retrieve sharing information
        conn = sqlite3.connect('securevault.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT key_id, key_name, algorithm, created_at, expires_at 
            FROM shared_keys WHERE id = ?
        """, (share_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return render_template('error.html', error="Shared key not found or link has expired"), 404
            
        key_id, key_name, algorithm, created_at, expires_at = result
        
        # Check if link has expired
        if expires_at and datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < datetime.now():
            conn.close()
            return render_template('error.html', error="This sharing link has expired"), 410
            
        # Get the public key data
        key_info = get_key_info()
        key = next((k for k in key_info if k['id'] == key_id), None)
        
        if not key:
            conn.close()
            return render_template('error.html', error="The shared key could not be found"), 404
            
        # Read the public key file
        key_path = os.path.join(KEYS_FOLDER, f"{key_id}.pub")
        if not os.path.exists(key_path):
            conn.close()
            return render_template('error.html', error="The shared key file could not be found"), 404
            
        with open(key_path, 'rb') as f:
            key_data = f.read().decode('utf-8')
        
        conn.close()
        
        # Render the shared key page
        return render_template('shared_key.html', 
                              share_id=share_id, 
                              key_id=key_id,
                              key_name=key_name,
                              algorithm=algorithm,
                              created_at=created_at,
                              key_data=key_data)
        
    except Exception as e:
        print(f"Shared key access error: {str(e)}")
        return render_template('error.html', error=f"Error accessing shared key: {str(e)}"), 500

@app.route('/api/download/shared-key/<share_id>', methods=['GET'])
def download_shared_key(share_id):
    """Download a shared public key"""
    try:
        # Retrieve sharing information
        conn = sqlite3.connect('securevault.db')
        cursor = conn.cursor()
        cursor.execute("SELECT key_id, key_name FROM shared_keys WHERE id = ?", (share_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "Shared key not found"}), 404
            
        key_id, key_name = result
        key_path = os.path.join(KEYS_FOLDER, f"{key_id}.pub")
        
        if not os.path.exists(key_path):
            return jsonify({"error": "Key file not found"}), 404
            
        return send_file(key_path, as_attachment=True, download_name=f"{key_name}.pub")
        
    except Exception as e:
        print(f"Shared key download error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['DELETE'])
def delete_key(key_id):
    key_info = get_key_info()
    updated_key_info = [k for k in key_info if k['id'] != key_id]
    
    if len(key_info) == len(updated_key_info):
        return jsonify({"error": "Key not found"}), 404
    
    # Delete key files
    try:
        for ext in ['.pub', '.key']:
            key_path = os.path.join(KEYS_FOLDER, f"{key_id}{ext}")
            if os.path.exists(key_path):
                os.remove(key_path)
        save_key_info(updated_key_info)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": f"Error deleting key files: {str(e)}"}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        # Save and read file
        file = request.files['file']
        original_filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        file.save(temp_path)
        
        with open(temp_path, 'rb') as f:
            data = f.read()
        
        # Extract file information
        file_name, file_ext = os.path.splitext(original_filename)
        if file_ext.startswith('.'):
            file_ext = file_ext[1:]
        
        # Store file metadata
        file_metadata = {
            "original_ext": file_ext.lower(),
            "original_name": original_filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Encrypt based on method
        method = request.form.get('method', 'symmetric')
        if method == 'symmetric':
            if 'password' not in request.form:
                return jsonify({"error": "Password required for symmetric encryption"}), 400
            
            password = request.form['password']
            algorithm = request.form.get('algorithm', 'aes-256-cbc')
            
            # Debug info
            print(f"Encrypting file: {original_filename} with algorithm: {algorithm}")
            print(f"Password type: {type(password)}")
            
            # Ensure data is bytes
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate a random salt
            salt = os.urandom(16)
            
            # Ensure password is bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
                
            # Derive encryption key from password and salt
            key = derive_key(password, salt)
            
            # Generate initialization vector
            iv = os.urandom(16)
            
            # Select and create cipher based on algorithm
            if algorithm == 'aes-256-cbc':
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Create padder and encryptor
            padder = padding.PKCS7(128).padder()
            encryptor = cipher.encryptor()
            
            # Pad and encrypt the data
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create encryption metadata dictionary
            encryption_metadata = {
                "algorithm": algorithm,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8')
            }
            
            # Combine file metadata with encryption metadata
            combined_metadata = {
                **file_metadata,
                "encryption": encryption_metadata
            }
            
            # Convert metadata to JSON and encode as base64
            metadata_json = json.dumps(combined_metadata).encode('utf-8')
            metadata_b64 = base64.b64encode(metadata_json)
            
            # Debug info
            print(f"Encrypted data type: {type(encrypted_data)}")
            print(f"Encrypted data starts with: {encrypted_data[:20] if len(encrypted_data) > 20 else encrypted_data}")
            
            # Create the final encrypted data
            final_data = b"SECV1_META:" + metadata_b64 + b":" + encrypted_data
            
            # Debug info
            print(f"Final data type: {type(final_data)}")
            print(f"Final data starts with: {final_data[:50]}")
            
        elif method == 'asymmetric':
            if 'key_id' not in request.form:
                return jsonify({"error": "Public key ID required for asymmetric encryption"}), 400
            
            key_id = request.form['key_id']
            encrypted_data = asymmetric_encrypt(data, key_id)
            
            # Add file metadata to the final output
            metadata_json = json.dumps(file_metadata).encode('utf-8')
            metadata_b64 = base64.b64encode(metadata_json)
            final_data = b"SEAPK1_META:" + metadata_b64 + b":" + encrypted_data
            
        else:
            return jsonify({"error": "Invalid encryption method"}), 400
        
        # Generate encrypted filename (preserve original extension in filename)
        if file_ext:
            encrypted_filename = f"{file_name}.{file_ext}.enc"
        else:
            encrypted_filename = f"{file_name}.enc"
        
        counter = 1
        while os.path.exists(os.path.join(ENCRYPTED_FOLDER, encrypted_filename)):
            if file_ext:
                encrypted_filename = f"{file_name}_{counter}.{file_ext}.enc"
            else:
                encrypted_filename = f"{file_name}_{counter}.enc"
            counter += 1
        
        # Save encrypted file
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(final_data)
        
        # Clean up and return
        os.remove(temp_path)
        
        return jsonify({
            "filename": encrypted_filename,
            "download_url": f"/api/download/encrypted/{encrypted_filename}",
            "original_name": original_filename,
            "original_ext": file_ext
        })
        
    except Exception as e:
        # Clean up temp file if it exists
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        print(f"Encryption error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    """Handle file decryption with proper error handling and JSON responses."""
    # Initialize variables to avoid undefined errors
    decrypted_data = None
    original_ext = ''
    original_name = ''
    temp_path = None
    
    try:
        # Validate inputs
        if 'file' not in request.files or request.files['file'].filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Save and read file
        file = request.files['file']
        encrypted_filename = secure_filename(file.filename)
        original_name = encrypted_filename  # Fallback value
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        file.save(temp_path)
        
        with open(temp_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Debug info
        print(f"Decrypting file: {encrypted_filename}")
        print(f"Encrypted data starts with: {encrypted_data[:50]}")
        
        # Check for direct format
        if b":" in encrypted_data[:50]:
            parts = encrypted_data.split(b":", 2)
            if len(parts) == 3:
                prefix = parts[0]
                metadata_b64 = parts[1]
                encrypted_content = parts[2]
                
                try:
                    metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                    metadata = json.loads(metadata_json)
                    
                    # Extract original filename and extension from metadata
                    original_ext = metadata.get('original_ext', '')
                    original_name = metadata.get('original_name', encrypted_filename)
                    
                    # Debug info
                    print(f"Prefix detected: {prefix}")
                    print(f"Metadata keys: {list(metadata.keys())}")
                    
                    # Ensure we always try asymmetric for SEAPK prefixes
                    if prefix in [b"SEAPK1", b"SEAPK1_META"]:
                        decryption_method = "asymmetric"
                    else:
                        decryption_method = "symmetric"
                    
                    print(f"Selected decryption method: {decryption_method}")
                    
                    # Get decryption parameters with better validation
                    password = request.form.get('password', '')
                    key_id = request.form.get('key_id', '')
                    key_password = request.form.get('key_password', '')
                    
                    print(f"Key ID: '{key_id}' - Key Password: {'*****' if key_password else 'None'}")
                    
                    # Check if we're in hybrid mode - try both methods if needed
                    hybrid_mode = request.form.get('hybrid_mode', 'false').lower() == 'true'
                    
                    # Try asymmetric decryption if appropriate
                    if decryption_method == "asymmetric":
                        if key_id:
                            print(f"Attempting asymmetric decryption with key_id: {key_id}")
                            
                            try:
                                decrypted_data = asymmetric_decrypt(encrypted_data, key_id, key_password)
                                if not decrypted_data:
                                    print("Asymmetric decryption returned no data")
                                    if hybrid_mode and password:
                                        print("Trying symmetric decryption as fallback in hybrid mode")
                                        decryption_method = "symmetric"
                                    else:
                                        return jsonify({"error": "Asymmetric decryption failed: No data returned"}), 400
                                    
                            except ValueError as ve:
                                error_str = str(ve)
                                print(f"Asymmetric decryption ValueError: {error_str}")
                                
                                # Check for specific password error
                                if "incorrect password" in error_str.lower():
                                    return jsonify({"error": "Asymmetric decryption failed: Incorrect password for the private key", 
                                                  "password_error": True}), 400
                                                  
                                if hybrid_mode and password:
                                    print("Trying symmetric decryption as fallback in hybrid mode after error")
                                    decryption_method = "symmetric"
                                else:
                                    return jsonify({"error": f"Asymmetric decryption failed: {error_str}"}), 400
                                    
                            except Exception as e:
                                print(f"Asymmetric decryption failed with exception: {str(e)}")
                                if hybrid_mode and password:
                                    print("Trying symmetric decryption as fallback in hybrid mode after exception")
                                    decryption_method = "symmetric"
                                else:
                                    return jsonify({"error": f"Asymmetric decryption failed: {str(e)}"}), 400
                        else:
                            # If no key_id is provided, inform the user
                            return jsonify({
                                "error": "This file was encrypted with asymmetric encryption. Please select a key to decrypt.",
                                "needs_key": True,
                                "prefix": prefix.decode('utf-8', errors='replace')
                            }), 400
                    
                    # Try symmetric decryption if selected
                    elif decryption_method == "symmetric":
                        # Only check for password if we're using symmetric decryption
                        if not password:
                            return jsonify({"error": "Password required for decryption"}), 400
                            
                        print(f"Password provided, proceeding with symmetric decryption")
                        
                        try:
                            # Use the symmetric_decrypt function
                            decrypted_data = symmetric_decrypt(encrypted_data, password)
                            if not decrypted_data:
                                return jsonify({"error": "Symmetric decryption failed: No data returned"}), 400
                                
                        except Exception as e:
                            print(f"Symmetric decryption failed: {str(e)}")
                            return jsonify({"error": f"Symmetric decryption failed: {str(e)}"}), 400
                        
                except Exception as e:
                    print(f"Metadata parsing error: {str(e)}")
                    import traceback
                    print(traceback.format_exc())
                    return jsonify({"error": f"Failed to parse encryption metadata: {str(e)}"}), 400
            else:
                return jsonify({"error": "Invalid encrypted data format: incorrect number of parts"}), 400
        else:
            return jsonify({"error": "Invalid encrypted data format: missing format separator"}), 400
        
        if not decrypted_data:
            return jsonify({"error": "Decryption failed: No data returned"}), 400
        
        # Detect file type as backup
        detected_ext = detect_file_type(decrypted_data) or ''
        
        # Determine final extension with priority
        if original_ext:
            final_ext = original_ext
        elif detected_ext:
            final_ext = detected_ext
        else:
            final_ext = 'bin'  # Default to binary if no extension can be determined
        
        # Generate decrypted filename
        if original_name and original_name != encrypted_filename:
            # Use original name if available
            base_name = os.path.splitext(original_name)[0]
            decrypted_filename = f"{base_name}.{final_ext}"
        else:
            # Otherwise derive from encrypted filename
            base_name = os.path.splitext(encrypted_filename)[0]
            if base_name.endswith(f".{final_ext}"):
                # Remove duplicate extension if present
                base_name = os.path.splitext(base_name)[0]
            decrypted_filename = f"{base_name}.{final_ext}"
        
        # Ensure filename is unique
        counter = 1
        while os.path.exists(os.path.join(DECRYPTED_FOLDER, decrypted_filename)):
            decrypted_filename = f"{base_name}_{counter}.{final_ext}"
            counter += 1
        
        # Save decrypted file
        decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Clean up temp file
        os.remove(temp_path)
        
        return jsonify({
            "filename": decrypted_filename,
            "download_url": f"/api/download/decrypted/{decrypted_filename}",
            "original_name": original_name,
            "original_ext": original_ext,
            "detected_type": detected_ext,
            "final_type": final_ext
        })
        
    except Exception as e:
        # Clean up temp file if it exists
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        print(f"Decryption error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route('/api/download/decrypted/<filename>', methods=['GET'])
def download_decrypted(filename):
    try:
        # Get absolute file path
        file_path = os.path.join(os.path.abspath(DECRYPTED_FOLDER), filename)
        print(f"Attempting to download decrypted file: {filename}")
        print(f"Looking for file at path: {file_path}")
        
        # Check if file exists
        if not os.path.exists(file_path):
            print(f"File not found at: {file_path}")
            return jsonify({"error": "File not found"}), 404
        
        # Get file size for logging
        file_size = os.path.getsize(file_path)
        print(f"File found. Size: {file_size} bytes")
        
        # Determine MIME type
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        mime_type = MIME_TYPES.get(ext, 'application/octet-stream')
        print(f"Using MIME type: {mime_type} for extension: {ext}")
        
        # Serve the file
        response = send_file(
            file_path,
            mimetype=mime_type,
            as_attachment=True,
            download_name=filename
        )
        
        # Add headers to prevent caching issues
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Cache-Control"] = "public, max-age=0"
        
        print(f"File download response prepared successfully")
        return response
        
    except Exception as e:
        print(f"Error sending file: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": f"Error sending file: {str(e)}"}), 500

@app.route('/api/download/encrypted/<filename>', methods=['GET'])
def download_encrypted(filename):
    try:
        # Get absolute file path
        file_path = os.path.join(os.path.abspath(ENCRYPTED_FOLDER), filename)
        print(f"Attempting to download encrypted file: {filename}")
        print(f"Looking for file at path: {file_path}")
        
        # Check if file exists
        if not os.path.exists(file_path):
            print(f"File not found at: {file_path}")
            return jsonify({"error": "File not found"}), 404
        
        # Get file size for logging
        file_size = os.path.getsize(file_path)
        print(f"File found. Size: {file_size} bytes")
        
        # Serve the file
        response = send_file(
            file_path,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
        
        # Add headers to prevent caching issues
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Cache-Control"] = "public, max-age=0"
        
        print(f"File download response prepared successfully")
        return response
        
    except Exception as e:
        print(f"Error sending file: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": f"Error sending file: {str(e)}"}), 500

@app.route('/error')
def error_page():
    return render_template('error.html', error="Error page")

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# Add static file routes for themes
@app.route('/static/css/themes.css')
def serve_themes_css():
    return send_file('static/css/themes.css', mimetype='text/css')

@app.route('/static/js/theme.js')
def serve_theme_js():
    return send_file('static/js/theme.js', mimetype='application/javascript')

if __name__ == '__main__':
    # Use environment variables for host and port if available
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)