#!/usr/bin/env python3
"""
Test script for secure_script_protector.py
This is a simple script to verify protection features.
"""

import datetime
import platform
import os


def get_system_info():
    """Return basic system information."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "current_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "working_directory": os.getcwd()
    }


def display_info():
    """Display system information."""
    info = get_system_info()
    print("\n===== System Information =====")
    for key, value in info.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    print("=============================\n")


def calculate_factorial(n):
    """Calculate the factorial of n."""
    if n < 0:
        return "Error: Factorial not defined for negative numbers"
    if n == 0 or n == 1:
        return 1
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def main():
    """Main function to demonstrate script functionality."""
    print("\nWelcome to the Test Script!")
    print("This script demonstrates basic functionality to test script protection.")
    
    # Display system information
    display_info()
    
    # Simple factorial calculator
    try:
        number = int(input("Enter a number to calculate its factorial: "))
        result = calculate_factorial(number)
        print(f"The factorial of {number} is: {result}")
    except ValueError:
        print("Please enter a valid number.")
    
    print("\nTest script execution completed successfully!")


if __name__ == "__main__":
    main()

