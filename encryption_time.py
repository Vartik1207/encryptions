import hashlib
import time

def hash_md5(data):
    """Compute MD5 hash of the given data."""
    return hashlib.md5(data).hexdigest()

def hash_sha1(data):
    """Compute SHA-1 hash of the given data."""
    return hashlib.sha1(data).hexdigest()

def hash_sha256(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def measure_time(hash_function, data):
    """Measure the time taken to compute the hash."""
    start_time = time.time()
    hash_value = hash_function(data)
    end_time = time.time()
    return hash_value, end_time - start_time

def main():
    while True:
        try:
            num_files = int(input("Enter the number of files: "))
            if num_files <= 0:
                print("Please enter a positive integer.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a numeric value.")

    while True:
        try:
            size_kb = int(input("Enter size of each file in KB: "))
            if size_kb <= 0:
                print("Please enter a positive integer.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a numeric value.")

    # Create a single byte string for all files
    size_bytes = size_kb * 1024  # Convert KB to bytes
    data = b'a' * size_bytes  # Create a byte string of 'a's

    # Measure hashing times for all files together
    md5_hash, md5_time = measure_time(hash_md5, data)
    sha1_hash, sha1_time = measure_time(hash_sha1, data)
    sha256_hash, sha256_time = measure_time(hash_sha256, data)

    # Print results for all files
    print(f"\nNumber of Files: {num_files} | Size of each file: {size_kb} KB")
    print(f"MD5 Time: {md5_time:.12f} seconds | MD5 Hash: {md5_hash}")
    print(f"SHA-1 Time: {sha1_time:.12f} seconds | SHA-1 Hash: {sha1_hash}")
    print(f"SHA-256 Time: {sha256_time:.12f} seconds | SHA-256 Hash: {sha256_hash}")
    print("-" * 70)

if __name__ == "__main__":
    main()