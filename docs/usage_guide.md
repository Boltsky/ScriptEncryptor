# ScriptEncryptor - Usage Guide

This comprehensive guide covers all aspects of using ScriptEncryptor to protect your Python scripts with multi-layer encryption, time-based expiration, and license management.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Protecting Scripts](#protecting-scripts)
- [License Management](#license-management)
- [Customization Options](#customization-options)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Installation

### Requirements

- Python 3.6 or higher
- Required packages: `cryptography`

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/boltsky/ScriptEncryptor.git
   cd ScriptEncryptor
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Basic Usage

ScriptEncryptor has an interactive interface that guides you through protecting scripts and managing licenses.

To start the tool:

```bash
python ScriptEncryptor.py
```

You will be presented with a menu offering the following options:
1. Protect a Python script
2. Generate a license key for reactivation
3. Exit

## Protecting Scripts

### Step-by-Step Guide

1. Select option 1 from the main menu.

2. Enter the path to the Python script you want to protect:
   ```
   Enter path to Python script to protect: examples/demo_script.py
   ```

3. Specify the output path (or leave blank for default):
   ```
   Enter path for protected output (leave blank for default): 
   ```
   Default output is named `protected_[original_name].py` in the same directory.

4. Set the number of encryption layers (10-1000):
   ```
   Enter number of encryption layers (10-1000): 200
   ```
   More layers increase security but may slightly impact startup time.

5. Enter the expiration date and time (in YYYY-MM-DD HH:MM:SS format):
   ```
   Enter expiration date/time (YYYY-MM-DD HH:MM:SS): 2026-01-01 00:00:00
   ```

6. Provide a message to display when the script expires:
   ```
   Enter message to display when script expires: This license has expired. Please contact support@example.com for renewal.
   ```

7. Decide whether to enable license reactivation:
   ```
   Enable license reactivation? (y/n): y
   ```
   If enabled, you can generate license keys to extend the expiration date.

8. Choose whether to display license information when the script runs:
   ```
   Display license information in the protected script? (y/n): y
   ```
   When enabled, a license box shows status, expiration, and warnings.

9. Optionally add contact information to display in the license box:
   ```
   Enter additional contact information to display:
   For support or license renewal, contact:
   Email: support@example.com
   Phone: +1-555-123-4567
   ```

The tool will then protect your script and provide the path to the protected file.

### Understanding the Protection Process

When you protect a script, the following happens:

1. Your original code is read and a hash is calculated for integrity verification
2. The code is encrypted with multiple layers (zlib, lzma, base64, Fernet)
3. A wrapper script is generated that contains the encrypted code and protection logic
4. If reactivation is enabled, RSA key pairs are generated
5. The protected script is saved to the specified output path

## License Management

### Enabling Reactivation

When protecting a script, answer "y" to the reactivation prompt. This generates:
- A public key embedded in the protected script
- A private key saved as `[script_name]_private.pem`

Keep the private key secure - it's required for generating license keys.

### Generating License Keys

To extend the expiration date of a protected script:

1. Select option 2 from the main menu

2. Enter the path to the private key file:
   ```
   Enter path to private key (*_private.pem): demo_script_private.pem
   ```

3. Specify the new expiration date:
   ```
   Enter expiration date/time (YYYY-MM-DD HH:MM:SS): 2027-01-01 00:00:00
   ```

4. The tool will generate a license key file named `[script_name]_license.key`

5. Place this license key file in the same directory as the protected script

When the protected script runs, it will automatically detect and validate the license key, updating the expiration date if the key is valid.

## Customization Options

### License Information Display

You can choose whether to display license information when the script runs. When enabled, a box is displayed showing:

- License status (Active/EXPIRED)
- Activation date
- Expiration date
- Time remaining
- Warning status based on time remaining
- Custom contact information (if provided)

To hide the license box, select "n" when prompted:
```
Display license information in the protected script? (y/n): n
```

### Contact Information

You can include custom contact information that appears in the license box:
```
Enter additional contact information to display:
Company: Example Corp
Email: licensing@example.com
Website: https://example.com/license
```

This helps users know how to contact you for support or license renewal.

## Security Considerations

### Strengths

- Multi-layer encryption makes static analysis difficult
- Time-based expiration controls usage period
- Code integrity verification prevents tampering
- License reactivation provides legitimate extension paths

### Limitations

- Protection runs in the Python interpreter and can potentially be bypassed
- Private keys must be kept secure to prevent unauthorized license generation
- Time-based protection relies on system time (which can be manipulated)

### Best Practices

- Use high layer counts (200+) for commercial scripts
- Generate unique keys for each protected script
- Store private keys securely, separate from the protected scripts
- Consider obfuscating variable names in your original script for added security
- Regularly update the protection tool to get security improvements

## Troubleshooting

### Common Issues

#### "License key validation failed"

- Ensure the license key file is in the same directory as the protected script
- Verify the license key was generated with the correct private key
- Check that the license key file hasn't been modified

#### "Script tampering detected"

- The protected script has been modified
- Re-protect the original script to fix this issue

#### Time zone related issues

- The tool handles time zones automatically
- All times are converted to UTC internally

#### Dependencies not found

- Ensure the `cryptography` package is installed:
  ```
  pip install cryptography
  ```

## FAQ

**Q: How secure is this protection?**

A: The protection is robust against casual inspection and basic reverse engineering attempts. It uses industry-standard cryptography and multiple layers of obfuscation. However, determined attackers with sufficient knowledge of Python could potentially bypass the protection. It's best used for deterrence and to protect against casual copying.

**Q: Will users need to install additional packages?**

A: Yes, users will need to have the `cryptography` package installed to run protected scripts.

**Q: Can I protect commercial software with this tool?**

A: Yes, but consider it as one layer in your overall software protection strategy. For commercial applications, you might want to combine this with other protection mechanisms.

**Q: What happens when a script expires?**

A: When a script expires, it will display the custom expiration message you defined and then exit without executing the protected code.

**Q: Can users modify the system time to bypass expiration?**

A: While the tool doesn't have specific protections against time manipulation, you can implement additional checks in your script (like online verification) if this is a concern.

