#!/usr/bin/env python3
"""
ScriptEncryptor

A powerful Python tool for protecting scripts with multi-layer encryption,
time-based expiration, and license management.

Author: boltsky (https://github.com/boltsky)
Repository: https://github.com/boltsky/ScriptEncryptor
Version: 1.0.0
"""

# Original notice:
# This tool is free and not for sale. Please do not sell it.
# Do not remove credits to appreciate our effort and encourage us to continue providing such (tools - bots - exploits)
# Trust in your creator. 
#==========================#
import base64
import hashlib
import json
import lzma
import os
import zlib
import pickle
import sys
from datetime import datetime, UTC, timezone
import datetime as dt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class ScriptEncryptor:
    """
    A powerful tool that combines multi-layer encryption with time-based protection
    and license management to secure Python scripts.
    
    Features:
    - Multi-layer encryption (configurable layers from 10-1000)
    - Time-based expiration
    - License management and reactivation
    - Code integrity verification
    - Custom expiration messages
    - Customizable license information display
    - Obfuscated output
    """
    def __init__(self):
        """Initialize the SecureScriptProtector with a Fernet key for encryption."""
        self.fernet_key = Fernet.generate_key()
        self.fernet = Fernet(self.fernet_key)
        
    def _generate_key_pair(self):
        """Generate RSA key pair for license management."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _multi_layer_encrypt(self, data, layers=10):
        """
        Encrypt data using multiple layers of compression and encoding.
        
        Args:
            data (str or bytes): The data to encrypt
            layers (int): Number of encryption layers (10-1000)
            
        Returns:
            bytes: The encrypted data
        """
        # Validate layers
        if not 10 <= layers <= 1000:
            raise ValueError("Encryption layers must be between 10 and 1000")
            
        # Convert string to bytes if it isn't already
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Apply multiple layers of encryption
        for _ in range(layers):
            data = zlib.compress(data)  # Compress with zlib
            data = lzma.compress(data)  # Compress with lzma
            data = base64.b85encode(data)  # Use base85 for better efficiency
            
        # Apply final Fernet encryption
        return self.fernet.encrypt(data)

    def _create_wrapper_code(self, encrypted_data, layers, expire_datetime, expire_message, 
                             code_hash, script_basename, enable_reactivation=False, public_key_data=None,
                             show_license_info=True, contact_info=None):
        """Create the wrapper code that contains the encrypted script and protection logic."""
        
        wrapper_code = f'''
import base64
import hashlib
import json
import lzma
import os
import sys
import zlib
from datetime import datetime, UTC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
# Encrypted data and keys
ENCRYPTED_DATA = {encrypted_data!r}
FERNET_KEY = {self.fernet_key!r}
LAYERS = {layers}
EXPIRE_DATETIME = "{expire_datetime}"
CODE_HASH = "{code_hash}"
SCRIPT_BASENAME = "{script_basename}"
ENABLE_REACTIVATION = {enable_reactivation}
SHOW_LICENSE_INFO = {show_license_info}
CONTACT_INFO = {contact_info!r}
EXPIRE_MESSAGE = {expire_message!r}
'''

        if enable_reactivation and public_key_data:
            wrapper_code += f'PUBLIC_KEY_DATA = """{public_key_data}"""\n'
        else:
            wrapper_code += 'PUBLIC_KEY_DATA = None\n'

        # Add decryption functions
        # Add decryption functions and time formatting
        wrapper_code += '''
def format_time_remaining(time_delta):
    """Format a timedelta into a human-readable string showing days, hours, minutes, seconds.
    
    This function is used to display the remaining time until script expiration in a user-friendly format.
    """
    # Extract components
    total_seconds = int(time_delta.total_seconds())
    if total_seconds <= 0:
        return "Expired"
        
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    
    # Format the string
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
    
    return ", ".join(parts)

def multi_layer_decrypt(encrypted_data, fernet_key, layers):
    """Decrypt data by reversing the multi-layer encryption process."""
    try:
        # First decrypt with Fernet
        fernet = Fernet(fernet_key)
        data = fernet.decrypt(encrypted_data)
        
        # Reverse the layers of encryption
        for _ in range(layers):
            data = base64.b85decode(data)  # Decode base85
            data = lzma.decompress(data)   # Decompress lzma
            data = zlib.decompress(data)   # Decompress zlib
            
        return data
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        sys.exit(1)
# Main execution routine
if __name__ == "__main__":
    # Log execution attempt with timestamps
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "execution_log.txt")
    with open(log_file, "a") as f:
        f.write(f"Execution attempt at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S.%f')} UTC\\n")
    
    try:
        # Decrypt the code
        decrypted_data = multi_layer_decrypt(ENCRYPTED_DATA, FERNET_KEY, LAYERS)
        
        # Verify code integrity
        current_hash = hashlib.sha256(decrypted_data).hexdigest()
        if current_hash != CODE_HASH:
            print("Script tampering detected! Code integrity check failed.")
            sys.exit(1)
        
        # Check expiration
        current_time = datetime.now(UTC)
        # Parse the expiration time and make it timezone-aware
        expire_time = datetime.strptime(EXPIRE_DATETIME, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        
        # Check for license reactivation
        # Check for license reactivation
        if ENABLE_REACTIVATION and PUBLIC_KEY_DATA:
            try:
                license_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{SCRIPT_BASENAME}_license.key")
                if os.path.exists(license_path):
                    public_key = serialization.load_pem_public_key(PUBLIC_KEY_DATA.encode())
                    with open(license_path, 'r') as f:
                        license_data = json.load(f)
                        new_expire = license_data['expire_datetime']
                        signature = bytes.fromhex(license_data['signature'])
                        
                        # Verify signature
                        public_key.verify(
                            signature,
                            new_expire.encode(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        # Update expiration time if license is valid
                        expire_time = datetime.strptime(new_expire, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                        print(f"License validated. New expiration: {new_expire}")
            except Exception as e:
                print(f"License validation failed: {str(e)}")
                # Continue with original expiration time
        
        # Display expiration information
        time_remaining = expire_time - current_time
        formatted_time = format_time_remaining(time_remaining)
        
        # Display license information if enabled
        if SHOW_LICENSE_INFO:
            # Enhanced license information display with double-line box characters and centered title
            title = "LICENSE INFORMATION"
            box_width = 60
            title_padding = (box_width - len(title)) // 2
            print(f"╔{'═' * box_width}╗")
            print(f"║{' ' * title_padding}{title}{' ' * (box_width - len(title) - title_padding)}║")
            print(f"╠{'═' * box_width}╣")
            status = 'Active' if time_remaining.total_seconds() > 0 else 'EXPIRED'
            activation_date = current_time.strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f"║  License Status:     {status}{' ' * (box_width - 21 - len(status))}║")
            print(f"║  Activation Date:    {activation_date}{' ' * (box_width - 21 - len(activation_date))}║")
            expire_str = expire_time.strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f"║  Expiration Date:    {expire_str}{' ' * (box_width - 21 - len(expire_str))}║")
            print(f"║  Time Remaining:     {formatted_time}{' ' * (box_width - 21 - len(formatted_time))}║")
            
            # Display contact information if provided
            if CONTACT_INFO:
                contact_info_lines = CONTACT_INFO.strip().split('\\n')
                print(f"╟{'─' * box_width}╢")
                print(f"║  Contact Information:{' ' * (box_width - 22)}║")
                for line in contact_info_lines:
                    if line:
                        print(f"║  {line}{' ' * (box_width - 3 - len(line))}║")
            
            # Add warning based on remaining time
            seconds_remaining = time_remaining.total_seconds()
            if seconds_remaining > 0:
                if seconds_remaining < 60:  # Less than 1 minute - FINAL COUNTDOWN
                    warning = f"⚠️ FINAL COUNTDOWN: Script expires in {int(seconds_remaining)} seconds!"
                    print(f"║  {'!' * 5} URGENT NOTICE {'!' * 5}{' ' * (box_width - 24)}║")
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
                    print(f"║  {'!' * 5} RENEW NOW {'!' * 5}{' ' * (box_width - 20)}║")
                elif seconds_remaining < 300:  # Less than 5 minutes
                    warning = "⚠️ URGENT: Script expires in less than 5 minutes!"
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
                elif seconds_remaining < 3600:  # Less than 1 hour
                    warning = "❗ CRITICAL: Less than 1 hour remaining"
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
                elif seconds_remaining < 86400:  # Less than 24 hours
                    warning = "❗ Warning: Less than 24 hours remaining"
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
                elif seconds_remaining < 604800:  # Less than 7 days
                    warning = "⚠ License expires in less than 7 days"
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
                elif seconds_remaining < 2592000:  # Less than 30 days
                    warning = "ℹ License expires in less than 30 days"
                    print(f"║  Warning Status:     {warning}{' ' * (box_width - 21 - len(warning))}║")
            
            print(f"╚{'═' * box_width}╝")
        
        # Check if script has expired
        if current_time > expire_time:
            print(EXPIRE_MESSAGE)
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "expired_logs.txt"), 'a') as f:
                f.write(f"Expired execution attempt at {current_time.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC\\n")
            sys.exit(0)
        
        # Execute the decrypted code
        exec(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"Error during execution: {str(e)}")
        sys.exit(1)
'''
        return wrapper_code

    def protect_script(self, input_path, output_path=None, layers=10, expire_datetime=None,
                      expire_message="This script has expired.", enable_reactivation=False,
                      show_license_info=True, contact_info=None):
        """
        Protect a Python script with multi-layer encryption and time-based protection.
        
        Args:
            input_path (str): Path to the Python script to protect
            output_path (str, optional): Path for the protected output script. If None, a default path is generated.
            layers (int): Number of encryption layers (10-1000)
            expire_datetime (str): Expiration date in "YYYY-MM-DD HH:MM:SS" format
            expire_message (str): Message to display when script expires
            enable_reactivation (bool): Whether to enable license reactivation
            show_license_info (bool): Whether to display license information box when script runs
            contact_info (str, optional): Additional contact information to display in the license box
            
        Returns:
            str: Path to the protected script
        """
        # Validate and process input_path
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        # Generate default output path if not provided
        # Extract script basename for file naming
        script_basename = os.path.splitext(os.path.basename(input_path))[0]
            
        if not output_path:
            output_path = os.path.join(os.path.dirname(input_path), f"protected_{script_basename}.py")
            
        # Validate layers
        if not 10 <= layers <= 1000:
            raise ValueError("Encryption layers must be between 10 and 1000")
            
        # Validate expiration datetime
        # Validate expiration datetime
        # Validate expiration datetime
        if expire_datetime:
            try:
                # Parse the input datetime and convert to UTC
                local_dt = datetime.strptime(expire_datetime, "%Y-%m-%d %H:%M:%S")
                local_tz = datetime.now(timezone.utc).astimezone().tzinfo
                local_dt = local_dt.replace(tzinfo=local_tz)
                utc_dt = local_dt.astimezone(UTC)
                expire_datetime = utc_dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise ValueError("Invalid datetime format. Use YYYY-MM-DD HH:MM:SS")
        else:
            # Default to 30 days from now (in UTC)
            expire_dt = datetime.now(UTC) + datetime.timedelta(days=30)
            expire_datetime = expire_dt.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                original_code = f.read()
        except UnicodeDecodeError:
            # Try with error handling if UTF-8 fails
            with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
                original_code = f.read()
                print("Warning: Some characters in the input file couldn't be decoded properly.")
        
        # Generate code hash for integrity verification
        code_hash = hashlib.sha256(original_code.encode()).hexdigest()
        
        # Generate RSA keys for license reactivation if enabled
        public_key_data = None
        if enable_reactivation:
            private_key, public_key = self._generate_key_pair()
            public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            # Save private key
            private_key_path = os.path.join(os.path.dirname(os.path.abspath(output_path)), f"{script_basename}_private.pem")
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
        # Multi-layer encrypt the code
        encrypted_data = self._multi_layer_encrypt(original_code, layers)
        
        # Create the wrapper code
        # Create the wrapper code
        wrapper_code = self._create_wrapper_code(
            encrypted_data, 
            layers, 
            expire_datetime, 
            expire_message, 
            code_hash, 
            script_basename,
            enable_reactivation, 
            public_key_data,
            show_license_info,
            contact_info
        )
        # Apply final obfuscation
        obfuscated_code = f"import base64; exec(base64.b64decode({base64.b64encode(wrapper_code.encode()).decode()!r}))"
        
        # Write the protected script
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
            
        return output_path
        
    def generate_license_key(self, private_key_path, new_expire_datetime, script_basename=None):
        """
        Generate a license key for reactivation.
        
        Args:
            private_key_path (str): Path to the private key file
            new_expire_datetime (str): New expiration date in "YYYY-MM-DD HH:MM:SS" format
            
        Returns:
            str: Path to the generated license key
        """
        # Validate expiration datetime
        try:
            # Parse the input datetime (assumed to be in local time)
            expire_dt = datetime.strptime(new_expire_datetime, "%Y-%m-%d %H:%M:%S")
            # We just validate the format here
        except ValueError:
            raise ValueError("Invalid datetime format. Use YYYY-MM-DD HH:MM:SS")
            
        # Load private key
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
            
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
            
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None
            )
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}")
            
        # Sign the new expiration date
        signature = private_key.sign(
            new_expire_datetime.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Create license data
        # Convert the expiration time to UTC for storage
        try:
            # Parse the input datetime
            local_dt = datetime.strptime(new_expire_datetime, "%Y-%m-%d %H:%M:%S")
            # Convert to UTC using proper timezone handling
            local_tz = datetime.now(timezone.utc).astimezone().tzinfo
            local_dt = local_dt.replace(tzinfo=local_tz)
            utc_dt = local_dt.astimezone(UTC)
            utc_expire = utc_dt.strftime("%Y-%m-%d %H:%M:%S")
            
            license_data = {
                'expire_datetime': utc_expire,
                'signature': signature.hex()
            }
        except ValueError:
            # Fallback if there's an issue with the conversion
            license_data = {
                'expire_datetime': new_expire_datetime,
                'signature': signature.hex()
            }
        
        # Extract script basename from private key path if not provided
        if script_basename is None:
            private_key_filename = os.path.basename(private_key_path)
            if "_private.pem" in private_key_filename:
                script_basename = private_key_filename.replace("_private.pem", "")
            else:
                # Fallback to a default name
                script_basename = "license"
        
        # Save license key
        license_path = os.path.join(os.path.dirname(os.path.abspath(private_key_path)), f"{script_basename}_license.key")
        with open(license_path, 'w') as f:
            json.dump(license_data, f, indent=2)
            
        return license_path

def get_valid_datetime():
    """Get a valid datetime string from user input."""
    while True:
        date_str = input("Enter expiration date/time (YYYY-MM-DD HH:MM:SS): ")
        try:
            datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            return date_str
        except ValueError:
            print("Invalid format! Please use YYYY-MM-DD HH:MM:SS format.")
            
def get_valid_layers():
    """Get a valid number of encryption layers from user input."""
    while True:
        try:
            layers = int(input("Enter number of encryption layers (10-1000): "))
            if 10 <= layers <= 1000:
                return layers
            else:
                print("Layers must be between 10 and 1000.")
        except ValueError:
            print("Please enter a valid number.")

def get_valid_path(prompt, must_exist=False):
    """Get a valid file path from user input."""
    while True:
        path = input(prompt).strip()
        if not path:
            return None
            
        if must_exist and not os.path.exists(path):
            print("File does not exist. Please enter a valid path.")
            continue
            
        return path
def main():
    """Main execution function."""
    VERSION = "1.0.0"
    print(r"""
     _____           _       _   _____                             _             
    /  ___|         (_)     | | |  ___|                           | |            
    \ `--.  ___ _ __ _ _ __ | |_| |__ _ __   ___ _ __ _   _ _ __ | |_ ___  _ __ 
     `--. \/ __| '__| | '_ \| __|  __| '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
    /\__/ / (__| |  | | |_) | |_| |__| | | | (__| |  | |_| | |_) | || (_) | |   
    \____/ \___|_|  |_| .__/ \__|____/_| |_|\___|_|   \__, | .__/ \__\___/|_|   
                       | |                              __/ | |                  
                       |_|                             |___/|_|                  
    """)
    print(f"Version: {VERSION}")
    print(f"GitHub: https://github.com/boltsky/ScriptEncryptor")
    print("\n" + "="*70)
    
    while True:
        print("Select operation:")
        print("1. Protect a Python script")
        print("2. Generate a license key for reactivation")
        print("3. Exit\n")
        
        try:
            choice = int(input("Enter choice (1-3): "))
            
            if choice == 1:
                # Protect a script
                input_file = get_valid_path("\nEnter path to Python script to protect: ", must_exist=True)
                if not input_file:
                    continue
                    
                output_file = get_valid_path("Enter path for protected output (leave blank for default): ")
                layers = get_valid_layers()
                expire_datetime = get_valid_datetime()
                expire_message = input("\nEnter message to display when script expires: ")
                enable_reactivation = input("\nEnable license reactivation? (y/n): ").lower() == 'y'
                show_license_info = input("\nDisplay license information in the protected script? (y/n): ").lower() == 'y'
                contact_info = None
                if show_license_info:
                    contact_info = input("\nEnter additional contact information to display (leave blank for none):\n")
                
                print("\nProtecting script...")
                protector = ScriptEncryptor()
                
                try:
                    output_path = protector.protect_script(
                        input_file,
                        output_file,
                        layers,
                        expire_datetime,
                        expire_message,
                        enable_reactivation,
                        show_license_info,
                        contact_info
                    )
                    
                    print(f"\nSuccess! Protected script saved to: {output_path}")
                    
                    if enable_reactivation:
                        script_basename = os.path.splitext(os.path.basename(output_file if output_file else output_path))[0]
                        if script_basename.startswith("protected_"):
                            script_basename = script_basename[len("protected_"):]
                        private_key_path = os.path.join(os.path.dirname(os.path.abspath(output_path)), f"{script_basename}_private.pem")
                        print(f"Private key saved to: {private_key_path}")
                        print("IMPORTANT: Keep the private key secure. It is required for license reactivation.")
                        
                except Exception as e:
                    print(f"Error: {str(e)}")
                    
            elif choice == 2:
                # Generate a license key
                private_key_path = get_valid_path("\nEnter path to private key (*_private.pem): ", must_exist=True)
                if not private_key_path:
                    continue
                    
                expire_datetime = get_valid_datetime()
                
                print("\nGenerating license key...")
                protector = ScriptEncryptor()
                
                try:
                    license_path = protector.generate_license_key(private_key_path, expire_datetime)
                    print(f"\nSuccess! License key saved to: {license_path}")
                except Exception as e:
                    print(f"Error: {str(e)}")
                    
            elif choice == 3:
                # Exit
                print("\nExiting ScriptEncryptor. Goodbye!")
                print("\nVisit https://github.com/boltsky/ScriptEncryptor for updates and new features.")
                break
                
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")
                
            print("\n" + "-"*70)
            input("Press Enter to continue...")
            
        except ValueError:
            print("\nInvalid input. Please enter a number.")
            print("\n" + "-"*70)
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
