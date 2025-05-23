# SecureVault - File Encryption Application

A Flask web application for secure file encryption and decryption.

## Deployment Instructions for Render

1. Create a Render account at [render.com](https://render.com)
2. Connect your GitHub repository to Render
3. Create a new Web Service
4. Use the following settings:
   - Name: securevault (or your preferred name)
   - Environment: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   - Select the Free plan

## Local Development

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:

   ```bash
   python app.py
   ```

## Features

- Symmetric and asymmetric encryption
- File encryption/decryption
- Key management
- User authentication
- QR code sharing for keys
