import hashlib
import os
import json
import time
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, config_file="file_hashes.json"):
        self.config_file = config_file
        self.file_hashes = {}
        self.load_hashes()
        
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(65536)  # Read in 64k chunks
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"Error accessing {filepath}: {str(e)}")
            return None

    def load_hashes(self):
        """Load previously stored hashes from config file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.file_hashes = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.file_hashes = {}

    def save_hashes(self):
        """Save current hashes to config file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.file_hashes, f, indent=4)

    def monitor_directory(self, directory, recursive=True):
        """Monitor all files in a directory"""
        if not os.path.exists(directory):
            print(f"Directory {directory} does not exist")
            return False

        current_hashes = {}
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    current_hashes[filepath] = file_hash
            
            if not recursive:
                break  # Only check top-level directory if recursive=False

        return self.compare_hashes(current_hashes)

    def compare_hashes(self, current_hashes):
        """Compare current hashes with stored hashes"""
        changes_detected = False
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check for modified files
        for filepath, current_hash in current_hashes.items():
            if filepath in self.file_hashes:
                if self.file_hashes[filepath] != current_hash:
                    print(f"[{now}] CHANGE DETECTED: {filepath}")
                    changes_detected = True
            else:
                print(f"[{now}] NEW FILE ADDED: {filepath}")
                changes_detected = True
        
        # Check for deleted files
        for filepath in self.file_hashes.keys():
            if filepath not in current_hashes:
                print(f"[{now}] FILE DELETED: {filepath}")
                changes_detected = True
        
        # Update stored hashes
        self.file_hashes = current_hashes
        self.save_hashes()
        
        return changes_detected

    def continuous_monitoring(self, directory, interval=60):
        """Continuously monitor directory at specified interval (seconds)"""
        print(f"Starting continuous monitoring of {directory} (interval: {interval}s)")
        try:
            while True:
                changes = self.monitor_directory(directory)
                if changes:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{now}] Integrity check completed - changes detected")
                else:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{now}] Integrity check completed - no changes detected")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("-i", "--interval", type=int, default=60,
                       help="Monitoring interval in seconds (default: 60)")
    parser.add_argument("-s", "--single", action="store_true",
                       help="Perform a single scan instead of continuous monitoring")
    parser.add_argument("-r", "--recursive", action="store_true",
                       help="Scan directories recursively")
    
    args = parser.parse_args()
    
    monitor = FileIntegrityMonitor()
    
    if args.single:
        monitor.monitor_directory(args.directory, recursive=args.recursive)
    else:
        monitor.continuous_monitoring(args.directory, interval=args.interval)
