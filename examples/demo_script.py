#!/usr/bin/env python3
"""
Demo Script for Secure Script Protector

This is a simple demonstration script that shows some functionality
that you might want to protect using the Secure Script Protector.
"""

import datetime
import platform
import os
import random
import time

# Define some sample credentials (simulating sensitive data)
API_KEY = "sk_live_demo_12345abcdef67890"
DATABASE_PASSWORD = "VerySecurePassword123!"
ADMIN_EMAIL = "admin@example.com"

class DemoCalculator:
    """A simple calculator class to demonstrate functionality."""
    
    def __init__(self):
        self.history = []
    
    def add(self, a, b):
        """Add two numbers and store in history."""
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result
    
    def subtract(self, a, b):
        """Subtract two numbers and store in history."""
        result = a - b
        self.history.append(f"{a} - {b} = {result}")
        return result
    
    def multiply(self, a, b):
        """Multiply two numbers and store in history."""
        result = a * b
        self.history.append(f"{a} * {b} = {result}")
        return result
    
    def divide(self, a, b):
        """Divide two numbers and store in history."""
        if b == 0:
            self.history.append(f"{a} / {b} = Error (division by zero)")
            raise ValueError("Cannot divide by zero")
        result = a / b
        self.history.append(f"{a} / {b} = {result}")
        return result
    
    def get_history(self):
        """Return calculation history."""
        return self.history

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

def generate_random_data():
    """Generate some random data (simulating proprietary algorithm)."""
    data = []
    for _ in range(10):
        data.append(random.randint(1, 100))
    return data

def process_data(data):
    """Process data with a proprietary algorithm."""
    # This is a simple algorithm, but in real-world cases,
    # this might be something you want to keep secret
    result = []
    for item in data:
        processed = (item * 2) + 10
        result.append(processed)
    return result

def main():
    """Main function to demonstrate script functionality."""
    print("\nWelcome to the Demo Script!")
    print("This script demonstrates functionality that you might want to protect.")
    
    # Display system information
    display_info()
    
    # Use the calculator
    calc = DemoCalculator()
    print("Performing some calculations...")
    calc.add(10, 5)
    calc.subtract(10, 3)
    calc.multiply(4, 5)
    
    try:
        calc.divide(10, 2)
        calc.divide(10, 0)  # This will raise an error
    except ValueError as e:
        print(f"Caught exception: {e}")
    
    # Display calculation history
    print("\nCalculation History:")
    for entry in calc.get_history():
        print(f"  {entry}")
    
    # Demonstrate proprietary algorithm
    print("\nGenerating random data...")
    data = generate_random_data()
    print(f"Raw data: {data}")
    
    print("\nProcessing data with proprietary algorithm...")
    processed = process_data(data)
    print(f"Processed data: {processed}")
    
    # Display API keys (sensitive information)
    print("\nSecret Information (this is what you want to protect):")
    print(f"API Key: {API_KEY}")
    print(f"Database Password: {DATABASE_PASSWORD}")
    print(f"Admin Email: {ADMIN_EMAIL}")
    
    print("\nDemo script execution completed.")

if __name__ == "__main__":
    main()

