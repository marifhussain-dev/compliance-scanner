import os

def scan_directory(path):

    """Scan directory and find all Python files"""

    python_file = []

    for root, dirs, files in os.walk(path):

        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                python_file.append(full_path)
    return python_file

def main():

    print("Starting security scanner...")
    files = scan_directory(".")

    print(f"\nFound {len(files)} Python files:")
    for f in files:
        print(f" -{f}")

if __name__ == "__main__":
    main()
