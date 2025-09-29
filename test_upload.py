#!/usr/bin/env python3
"""
Test Python file for security analysis
Contains intentional security vulnerabilities for testing
"""

import os
import subprocess
import pickle

# SQL Injection vulnerability
def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

# Command injection vulnerability
def unsafe_command(filename):
    os.system(f"cat {filename}")

# Pickle deserialization vulnerability
def unsafe_deserialize(data):
    return pickle.loads(data)

# Hard-coded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

if __name__ == "__main__":
    print("Test file for security analysis")