"""
Author: <Noela Kabundi>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

import sys
print(f"Python version: {sys.version}")
print(f"Operating System: {platform.system()}")

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}

class NetworkTool:
    """Parent class providing a validated, encapsulated target attribute."""
 
    def __init__(self, target: str):
        # Use the setter so validation runs at construction time too
        self.target = target
 
    @property
    def target(self) -> str:
        return self.__target
 
    @target.setter
    def target(self, value: str):
        if value == "":
            raise ValueError("Target cannot be an empty string.")
        self.__target = value
 
    def __del__(self):
        print("NetworkTool instance destroyed")

# Q3: What is the benefit of using @property and @target.setter?
# Using @property and @target.setter encapsulates access to the private __target
# attribute, preventing direct external modification. The setter lets us add
# validation logic (like rejecting empty strings) in a single, controlled place.
# This approach follows the principle of data hiding — callers use scanner.target
# like a plain attribute, but our class silently enforces the rules behind the scenes.

# Q1: How does PortScanner reuse code from NetworkTool?
# # PortScanner inherits from NetworkTool, so it automatically gains the validated
# target property and its getter/setter without duplicating any of that logic.
# The call to super().__init__(target) in PortScanner's constructor delegates
# attribute initialisation to NetworkTool, keeping the child class focused only
# on scanning behaviour. This is classic inheritance-based code reuse: shared
# structure lives in the parent, specialised behaviour lives in the child.

class PortScanner(NetworkTool):
    """Child class that performs multi-threaded TCP port scanning."""
 
    def __init__(self, target: str):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()
 
    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()
    
    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, socket errors like connection timeouts or refused
        # connections would crash the entire scan instead of being handled gracefully.
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            
            service_name = common_ports.get(port, "Unknown")
            
            with self.lock:
                self.scan_results.append((port, status, service_name))
                
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()
    
    def get_open_ports(self):
        # Q2: Why do we use threading instead of scanning one port at a time?
        # Threading allows multiple ports to be scanned simultaneously, dramatically
        # reducing total scan time. This is especially important for network operations
        # which have high latency compared to CPU operations.
        return [result for result in self.scan_results if result[1] == "Open"]
    
    def scan_range(self, start_port, end_port):
        threads = []
        
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()

def save_results(target, results):
    """Save scan results to SQLite database."""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                service TEXT NOT NULL,
                scan_date TEXT NOT NULL
            )
        ''')
        
        for port, status, service in results:
            cursor.execute('''
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, port, status, service, datetime.datetime.now()))
        
        conn.commit()
        conn.close()
        print(f"Results saved to database for {target}")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    """Load and display past scan history from database."""
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC')
        scans = cursor.fetchall()
        
        if not scans:
            print("No past scans found.")
        else:
            print("\n=== Past Scan History ===")
            for scan in scans:
                print(f"ID: {scan[0]}, Target: {scan[1]}, Port: {scan[2]}, "
                      f"Status: {scan[3]}, Service: {scan[4]}, Date: {scan[5]}")
        
        conn.close()
        
    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # Get user input with try-except
    while True:
        try:
            target_input = input("Enter target IP (default: 127.0.0.1): ").strip()
            target = target_input if target_input else "127.0.0.1"
            
            start_port = int(input("Enter start port (1-1024): "))
            if not 1 <= start_port <= 1024:
                print("Port must be between 1 and 1024.")
                continue
                
            end_port = int(input("Enter end port (1-1024, >= start port): "))
            if not 1 <= end_port <= 1024 or end_port < start_port:
                print("Port must be between 1 and 1024 and >= start port.")
                continue
                
            break
            
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
    
    # After valid input
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    
    scanner.scan_range(start_port, end_port)
    
    open_ports = scanner.get_open_ports()
    print("\n=== Scan Results ===")
    
    if open_ports:
        print("Open ports found:")
        for port, status, service in open_ports:
            print(f"  Port {port}: {service}")
        print(f"Total open ports: {len(open_ports)}")
    else:
        print("No open ports found.")
    
    save_results(target, scanner.scan_results)
    
    history_choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if history_choice == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# Add port service detection by connecting to open ports and analyzing banner
# information to identify specific software versions and services running on
# each port, providing more detailed reconnaissance capabilities.
# Diagram: See diagram_studentID.png in the repository root
