import os

# Create necessary folders for the application
folders = ['uploads', 'encrypted', 'decrypted', 'keys']

for folder in folders:
    os.makedirs(folder, exist_ok=True)
    print(f"Created folder: {folder}")

print("All required folders have been created.")
