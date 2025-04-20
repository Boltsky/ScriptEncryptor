# Example Scripts

This directory contains example scripts that demonstrate the use of the Secure Script Protector.

## Demo Script

The `demo_script.py` file is a simple demonstration script that shows functionality you might want to protect:

- Basic calculator functions
- System information display
- Data processing algorithms
- Sensitive information (API keys, passwords)

### How to Use the Demo Script

1. Run the script directly:
   ```
   python demo_script.py
   ```

2. Protect the script using Secure Script Protector:
   ```
   python ../src/secure_script_protector.py
   ```
   Follow the prompts to protect the demo script.

3. Run the protected version:
   ```
   python protected_demo_script.py
   ```

## Protecting Your Own Scripts

To protect your own scripts:

1. Make sure your script is working correctly first
2. Use the Secure Script Protector to encrypt it
3. Set appropriate expiration dates and messages
4. Choose whether to display license information
5. Distribute only the protected version

## Best Practices

- Set reasonable expiration dates based on your use case
- Use descriptive expiration messages that guide users
- Add contact information to help users get license renewals
- For commercial scripts, enable license reactivation
- Test your protected scripts thoroughly before distribution

