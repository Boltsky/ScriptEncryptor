# Secure Script Protector

A powerful Python tool for protecting your scripts with multi-layer encryption, time-based expiration, and license management.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)

## Features

- **Multi-layer Encryption:** Secures your code with 10-1000 layers of encryption
- **Time-based Expiration:** Set an expiration date for your protected scripts
- **License Management:** Generate license keys for reactivation
- **Code Integrity Verification:** Ensures your code hasn't been tampered with
- **Custom Expiration Messages:** Set personalized messages for expired scripts
- **Customizable License Display:** Option to show/hide license information
- **Contact Information:** Include custom contact details in the license box

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-script-protector.git
   cd secure-script-protector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Protecting a Script

```bash
python secure_script_protector.py
```

Follow the interactive prompts:
1. Select option 1 to protect a script
2. Enter the path to the Python script you want to protect
3. Specify output path (or leave blank for default)
4. Set the number of encryption layers (10-1000)
5. Enter expiration date/time in YYYY-MM-DD HH:MM:SS format
6. Provide a message to display when the script expires
7. Choose whether to enable license reactivation
8. Choose whether to display license information when the script runs
9. Optionally add contact information to display in the license box

### Generating a License Key for Reactivation

If you enabled reactivation when protecting a script:

```bash
python secure_script_protector.py
```

1. Select option 2 to generate a license key
2. Enter the path to the private key file (`*_private.pem`)
3. Specify the new expiration date/time

## How It Works

1. **Script Protection:**
   - Your Python code is encrypted with multiple layers (zlib, lzma, base64, Fernet)
   - A wrapper script is generated that handles decryption and execution
   - The protected script checks for expiration and integrity before executing
   
2. **License Management:**
   - RSA key pairs are generated for scripts with reactivation enabled
   - License keys are digitally signed to prevent tampering
   - The protected script verifies license key signatures at runtime

3. **Customizable License Display:**
   - Option to show or hide the license information box
   - Customizable contact information for support or license renewal
   - Dynamic warnings based on remaining time until expiration

## Examples

See the [examples](./examples/) directory for sample scripts and usage demonstrations.

## Security Considerations

- Keep your private key files (`*_private.pem`) secure
- The protection is robust but not unbreakable (no protection is)
- This tool is designed to deter casual users from accessing your code
- For commercial applications, consider additional protection mechanisms

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and legitimate use cases only. The author is not responsible for any misuse or illegal activities conducted with this tool.

