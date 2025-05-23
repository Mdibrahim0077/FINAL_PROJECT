// Initialize functionality when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM fully loaded");
    // Detect which page we're on
    const currentPath = window.location.pathname;
    console.log("Current path:", currentPath);
    
    // Initialize page-specific functionality
    if (currentPath.includes('/encrypt')) {
        initializeEncryptPage();
    } else if (currentPath.includes('/decrypt')) {
        initializeDecryptPage();
    } else if (currentPath.includes('/keys')) {
        initializeKeysPage();
    } else if (currentPath.includes('/dashboard')) {
        // Dashboard needs no special initialization
    }

    // Functionality common to all pages
    if (document.getElementById('encrypt-form')) {
        document.getElementById('encrypt-form').addEventListener('submit', handleEncrypt);
            }
    
    if (document.getElementById('decrypt-form')) {
        document.getElementById('decrypt-form').addEventListener('submit', handleDecrypt);
    }
});

function initializeEncryptPage() {
    // Switch between symmetric/asymmetric encryption
    const encryptMethod = document.getElementById('encrypt-method');
    if (encryptMethod) {
    encryptMethod.addEventListener('change', () => {
        const isSymmetric = encryptMethod.value === 'symmetric';
        document.getElementById('encrypt-password-group').style.display = isSymmetric ? 'block' : 'none';
        document.getElementById('encrypt-algorithm-group').style.display = isSymmetric ? 'block' : 'none';
        document.getElementById('encrypt-key-group').style.display = isSymmetric ? 'none' : 'block';
    });
    }
    
    // Initialize file upload functionality
    const fileInput = document.getElementById('encrypt-file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const fileName = file.name;
                const selectedFileName = document.getElementById('selected-file-name');
                if (selectedFileName) {
                    selectedFileName.textContent = `Selected: ${fileName}`;
                    selectedFileName.style.display = 'block';
                }
                
                // Show file information
                showFileInfo(file, fileInput);
            }
        });
    }
    
    // Set up drag and drop for file upload
    const fileUploadArea = document.getElementById('file-upload-area');
    if (fileUploadArea && fileInput) {
        fileUploadArea.addEventListener('click', () => {
            fileInput.click();
        });
        
        fileUploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.style.borderColor = 'var(--primary)';
            fileUploadArea.style.backgroundColor = 'var(--hover-bg)';
        });
        
        fileUploadArea.addEventListener('dragleave', () => {
            fileUploadArea.style.borderColor = 'var(--border-color)';
            fileUploadArea.style.backgroundColor = 'var(--upload-bg)';
        });
        
        fileUploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.style.borderColor = 'var(--border-color)';
            fileUploadArea.style.backgroundColor = 'var(--upload-bg)';
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                const fileName = e.dataTransfer.files[0].name;
                
                // Update selected file name
                const selectedFileName = document.getElementById('selected-file-name');
                if (selectedFileName) {
                    selectedFileName.textContent = `Selected: ${fileName}`;
                    selectedFileName.style.display = 'block';
                }
                
                // Show file information
                showFileInfo(e.dataTransfer.files[0], fileInput);
            }
        });
    }
    
    // Load available keys for encryption
    loadKeys('public');
    }
    
function initializeDecryptPage() {
    // Initialize file input handling
    const fileInput = document.getElementById('decrypt-file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Show file information
                showFileInfo(file, fileInput);
                
                // Detect encryption method from file name or content
                detectEncryptionMethod(file);
            }
        });
    }
    
    // Add drop event listeners to file upload area
    const fileUploadArea = document.getElementById('file-upload-area');
    if (fileUploadArea && fileInput) {
        fileUploadArea.addEventListener('click', () => {
            fileInput.click();
        });
        
        fileUploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.style.borderColor = '#3182ce';
            fileUploadArea.style.backgroundColor = '#f7fafc';
        });
        
        fileUploadArea.addEventListener('dragleave', () => {
            fileUploadArea.style.borderColor = '#cbd5e0';
            fileUploadArea.style.backgroundColor = 'white';
        });
        
        fileUploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.style.borderColor = '#cbd5e0';
            fileUploadArea.style.backgroundColor = 'white';
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                const fileName = e.dataTransfer.files[0].name;
                
                // Update selected file name
                const selectedFileName = document.getElementById('selected-file-name');
                if (selectedFileName) {
                    selectedFileName.textContent = `Selected: ${fileName}`;
                    selectedFileName.style.display = 'block';
                }
                
                // Show file information
                showFileInfo(e.dataTransfer.files[0], fileInput);
                
                // Detect encryption method from file name or content
                detectEncryptionMethod(e.dataTransfer.files[0]);
            }
        });
    }
    
    // Initially hide all encryption-specific form groups
    const passwordGroup = document.getElementById('decrypt-password-group');
    const keyGroup = document.getElementById('decrypt-key-group');
    const keyPasswordGroup = document.getElementById('decrypt-key-password-group');
    
    if (passwordGroup) passwordGroup.style.display = 'none';
    if (keyGroup) keyGroup.style.display = 'none';
    if (keyPasswordGroup) keyPasswordGroup.style.display = 'none';
    
    // Load available keys for decryption
    loadKeys('private');
    
    // Add event listener for key selection
    const keySelect = document.getElementById('decrypt-key');
    if (keySelect) {
        keySelect.addEventListener('change', () => {
            const keyPasswordGroup = document.getElementById('decrypt-key-password-group');
            if (keyPasswordGroup) {
                keyPasswordGroup.style.display = keySelect.value ? 'block' : 'none';
            }
        });
    }
}

function showFileInfo(file, fileInput) {
    const fileInfo = document.createElement('div');
    fileInfo.className = 'selected-file-info';
    fileInfo.innerHTML = `
        <div class="alert alert-info">
            <p><strong>Selected File:</strong> ${file.name}</p>
            <p><strong>Size:</strong> ${formatFileSize(file.size)}</p>
        </div>
    `;
    
    // Remove any existing file info
    const parent = fileInput.parentElement;
    if (parent) {
        const existingInfo = parent.querySelector('.selected-file-info');
        if (existingInfo) {
            existingInfo.remove();
        }
        
        // Add new file info
        parent.appendChild(fileInfo);
    }
}

function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.getAttribute('data-tab') === tabId);
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tabId);
    });
}

// Function to load keys (public/private) into select elements
async function loadKeys(type) {
    try {
        const response = await fetch(`/api/keys?type=${type}`);
        const keys = await response.json();
        
        if (keys.error) {
            console.error("Error loading keys:", keys.error);
            return;
        }
        
        // Populate key select elements
        if (type === 'public') {
            const keySelect = document.getElementById('encrypt-key');
            if (keySelect) {
                // Clear existing options except the first one
                while (keySelect.options.length > 1) {
                    keySelect.remove(1);
                }
                
                // Add key options
                keys.forEach(key => {
                    const option = document.createElement('option');
                    option.value = key.id;
                    option.textContent = key.name || `Key ${key.id}`;
                    keySelect.appendChild(option);
                });
                
                // Add share button next to the key dropdown
                const keyGroup = document.getElementById('encrypt-key-group');
                if (keyGroup) {
                    // Remove existing share button if any
                    const existingShareBtn = keyGroup.querySelector('.key-share-btn');
                    if (existingShareBtn) {
                        existingShareBtn.remove();
                    }
                    
                    // Create a wrapper for the key select and share button if it doesn't exist
                    let keySelectWrapper = keyGroup.querySelector('.key-select-wrapper');
                    if (!keySelectWrapper) {
                        keySelectWrapper = document.createElement('div');
                        keySelectWrapper.className = 'key-select-wrapper';
                        keySelectWrapper.style.display = 'flex';
                        keySelectWrapper.style.gap = '10px';
                        keySelectWrapper.style.alignItems = 'center';
                        
                        // Move the select element into the wrapper
                        const selectParent = keySelect.parentNode;
                        keySelectWrapper.appendChild(keySelect);
                        
                        // Find the position to insert the wrapper (before the help text)
                        const helpText = keyGroup.querySelector('.help-text');
                        if (helpText) {
                            keyGroup.insertBefore(keySelectWrapper, helpText);
                        } else {
                            keyGroup.appendChild(keySelectWrapper);
                        }
                    }
                    
                    // Add share button for the currently selected key
                    const shareBtn = document.createElement('button');
                    shareBtn.type = 'button';
                    shareBtn.className = 'btn btn-sm btn-primary key-share-btn';
                    shareBtn.textContent = 'Share Key';
                    shareBtn.style.marginLeft = '10px';
                    shareBtn.style.flexShrink = '0';
                    shareBtn.onclick = function() {
                        const selectedKeyId = keySelect.value;
                        if (selectedKeyId) {
                            shareKey(selectedKeyId);
                        } else {
                            showError('Please select a key to share');
                        }
                    };
                    keySelectWrapper.appendChild(shareBtn);
                    
                    // Update share button when key selection changes
                    keySelect.addEventListener('change', function() {
                        shareBtn.disabled = !this.value;
                    });
                    
                    // Initially disable share button if no key is selected
                    shareBtn.disabled = !keySelect.value;
                }
            }
        } else if (type === 'private') {
            const keySelect = document.getElementById('decrypt-key');
            if (keySelect) {
                // Clear existing options except the first one
                while (keySelect.options.length > 1) {
                    keySelect.remove(1);
                }
                
                // Add key options
                keys.forEach(key => {
                    const option = document.createElement('option');
                    option.value = key.id;
                    option.textContent = key.name || `Key ${key.id}`;
                    keySelect.appendChild(option);
                });
            }
        }
    } catch (error) {
        console.error("Failed to load keys:", error);
    }
}



// Function to initialize the keys page
function initializeKeysPage() {
    // Set up form submission handlers
    const createKeyForm = document.getElementById('create-key-form');
    if (createKeyForm) {
        createKeyForm.addEventListener('submit', handleCreateKey);
    }
    
    const importKeyForm = document.getElementById('import-key-form');
    if (importKeyForm) {
        importKeyForm.addEventListener('submit', handleImportKey);
    }
    
    // Set up create key button
    const createKeyBtn = document.getElementById('create-key-btn');
    if (createKeyBtn) {
        createKeyBtn.addEventListener('click', showCreateKeyModal);
    }
    
    // Load existing keys
    loadKeysList();
        
    // Set up tab switching
    const tabs = document.querySelectorAll('.tab');
    if (tabs.length) {
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                switchTab(tab.getAttribute('data-tab'));
            });
        });
    }
}

// Function to load the list of keys for the keys page
async function loadKeysList() {
    try {
        const response = await fetch('/api/keys');
        const keys = await response.json();
        
        if (keys.error) {
            showError(keys.error);
            return;
        }
        
        const keysList = document.getElementById('keys-list');
        if (!keysList) return;
        
        // Remove the centering styles
        keysList.style.display = '';
        keysList.style.flexDirection = '';
        keysList.style.alignItems = '';
        keysList.style.gap = '';
        
        // Clear existing keys
        keysList.innerHTML = '';
        
        if (keys.length === 0) {
            keysList.innerHTML = '<div class="empty-state">No keys found. Create or import a key pair to get started.</div>';
            return;
        }
                
        // Add keys to the list
        keys.forEach(key => {
            // Handle date formatting - check both created_at and created fields
            let dateStr = 'Unknown date';
            if (key.created_at) {
                dateStr = new Date(key.created_at).toLocaleString();
            } else if (key.created) {
                dateStr = new Date(key.created).toLocaleString();
            }
            
            const keyCard = document.createElement('div');
            keyCard.className = 'key-card';
            // Remove centering styles from key cards
            keyCard.style.width = '';
            keyCard.style.maxWidth = '';
            keyCard.style.margin = '';
            keyCard.innerHTML = `
                <div class="key-info">
                    <h3>${key.name || 'Unnamed Key'}</h3>
                    <p><strong>ID:</strong> ${key.id}</p>
                    <p><strong>Type:</strong> ${key.type === 'public' ? 'Public Key' : 'Private Key'}</p>
                    <p><strong>Created:</strong> ${dateStr}</p>
                </div>

                <div class="key-actions">
                    <button class="btn btn-sm btn-danger" onclick="deleteKey('${key.id}')">Delete</button>
                </div>
            `;
            keysList.appendChild(keyCard);
        });
    } catch (error) {
        console.error("Failed to load keys list:", error);
        showError("Failed to load keys. Please try again.");
    }
}

// Function to handle key creation
async function handleCreateKey(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    
    try {
        const response = await fetch('/api/keys', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.error) {
            throw new Error(result.error);
        }
        
        showSuccess('Key pair created successfully!');
        
        // Reset form and close modal
        form.reset();
        const modal = document.getElementById('create-key-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        
        // Reload keys list
        loadKeysList();
    } catch (error) {
        showError(error.message || 'Failed to create key pair');
        console.error('Key creation error:', error);
    }
}

// Function to handle key import
async function handleImportKey(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    
    try {
        const response = await fetch('/api/keys/import', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.error) {
            throw new Error(result.error);
        }
        
        showSuccess('Key imported successfully!');
        
        // Reset form and close modal
        form.reset();
        const modal = document.getElementById('import-key-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        
        // Reload keys list
        loadKeysList();
    } catch (error) {
        showError(error.message || 'Failed to import key');
        console.error('Key import error:', error);
    }
}

// Function to delete a key
async function deleteKey(keyId) {
    if (!confirm('Are you sure you want to delete this key? This action cannot be undone.')) {
        return;
            }
    
    try {
        const response = await fetch(`/api/keys/${keyId}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        if (result.error) {
            throw new Error(result.error);
        }
        
        showSuccess('Key deleted successfully!');
        
        // Reload keys list
        loadKeysList();
    } catch (error) {
        showError(error.message || 'Failed to delete key');
        console.error('Key deletion error:', error);
    }
}

async function handleEncrypt(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    
    // Get the submit button
    const submitButton = form.querySelector('button[type="submit"]');
    let originalButtonText = '';
    if (submitButton) {
        originalButtonText = submitButton.textContent;
        submitButton.textContent = 'Encrypting...';
        submitButton.disabled = true;
    }
    
    try {
        // Validate inputs
        const file = form.querySelector('#encrypt-file').files[0];
        if (!file) {
            throw new Error('Please select a file to encrypt');
        }
        
        const method = formData.get('method');
        if (method === 'symmetric') {
            const password = formData.get('password');
            if (!password) {
                throw new Error('Please enter a password for encryption');
            }
        } else if (method === 'asymmetric') {
            const keyId = formData.get('key_id');
            if (!keyId) {
                throw new Error('Please select a public key for encryption');
            }
        }
        
        // Send request to server
        const response = await fetch('/api/encrypt', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Encryption failed');
        }
        
        const result = await response.json();
        
        // Show success message and download link
        const resultBox = document.getElementById('result-container');
        if (resultBox) {
            resultBox.style.display = 'block';
            
            // Set download link
            const downloadLink = document.getElementById('download-link');
            const directDownloadBtn = document.getElementById('direct-download-btn');
            
            if (downloadLink) {
                downloadLink.href = result.download_url;
                downloadLink.download = result.filename;
                
                // Add click event to ensure download works
                downloadLink.onclick = function(e) {
                    // Don't prevent default to allow native download behavior first
                    
                    // Show loading message
                    showSuccess('Starting download...');
                    
                    // Show direct download button after a delay if the main download might have failed
                    setTimeout(() => {
                        if (directDownloadBtn) {
                            directDownloadBtn.style.display = 'inline-block';
                        }
                    }, 3000);
                };
            }
            
            // Setup direct download button as fallback
            if (directDownloadBtn) {
                directDownloadBtn.onclick = function() {
                    // Force download through window.location
                    window.location.href = result.download_url;
                    showSuccess('Trying alternative download method...');
                };
            }
            
            // Store the filename
            resultBox.dataset.filename = result.filename;
        }
        
        // Reset form
        form.reset();
        
        // Reset form state
        if (submitButton) {
            submitButton.textContent = originalButtonText;
            submitButton.disabled = false;
        }
        
        // Remove file info
        const fileInfo = form.querySelector('.selected-file-info');
        if (fileInfo) {
            fileInfo.remove();
        }
        
        // Reset file name display
        const selectedFileName = document.getElementById('selected-file-name');
        if (selectedFileName) {
            selectedFileName.style.display = 'none';
        }
        
    } catch (error) {
        console.error('Encryption error:', error);
        showError(error.message);
        
        // Reset button state
        if (submitButton) {
            submitButton.textContent = originalButtonText;
            submitButton.disabled = false;
        }
    }
}

async function handleDecrypt(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    
    try {
        // Show loading indicator
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.textContent;
        submitButton.textContent = 'Decrypting...';
        submitButton.disabled = true;
        
        // Validate file input
        const fileInput = document.getElementById('decrypt-file');
        if (!fileInput || !fileInput.files || !fileInput.files[0]) {
            throw new Error('Please select a file to decrypt');
        }
        
        const file = fileInput.files[0];
        
        // Check if password field is visible (symmetric decryption)
        const passwordGroup = document.getElementById('decrypt-password-group');
        const isPasswordVisible = passwordGroup && window.getComputedStyle(passwordGroup).display !== 'none';
        
        // Check if key field is visible (asymmetric decryption)
        const keyGroup = document.getElementById('decrypt-key-group');
        const isKeyVisible = keyGroup && window.getComputedStyle(keyGroup).display !== 'none';
        
        // Validate decryption method
        if (isPasswordVisible) {
            // For symmetric encryption, validate password
            const password = document.getElementById('decrypt-password').value;
            if (!password) {
                throw new Error('Please enter a password for decryption');
            }
            formData.set('method', 'symmetric');
            formData.set('password', password);
        } else if (isKeyVisible) {
            // For asymmetric encryption, validate key selection
            const keyId = document.getElementById('decrypt-key').value;
            if (!keyId) {
                throw new Error('Please select a private key for decryption');
            }
            
            // Check if key password is needed
            const keyPasswordGroup = document.getElementById('decrypt-key-password-group');
            const isKeyPasswordVisible = keyPasswordGroup && 
                                        window.getComputedStyle(keyPasswordGroup).display !== 'none';
            
            if (isKeyPasswordVisible) {
            const keyPassword = document.getElementById('decrypt-key-password').value;
                formData.set('key_password', keyPassword);
            }
            
            formData.set('method', 'asymmetric');
            formData.set('key_id', keyId);
        }

        const response = await fetch('/api/decrypt', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            // Try to parse response as JSON first
            let errorData;
            try {
                errorData = await response.json();
                
                if (errorData.error) {
                    throw new Error(errorData.error);
                }
            } catch (jsonError) {
                    throw jsonError;
                }
        }
        
        const result = await response.json();
        if (result.error) {
            throw new Error(result.error);
        }
        
        // Show file type information
        const fileTypeInfo = document.createElement('div');
        fileTypeInfo.className = 'file-info';
        fileTypeInfo.innerHTML = `
            <div class="alert alert-success">
                <h4>File Decrypted Successfully!</h4>
                <p>Original filename: ${result.original_name || 'Unknown'}</p>
                <p>Detected file type: ${(result.detected_type || 'unknown').toUpperCase()}</p>
                <p>Final file type: ${(result.final_type || 'unknown').toUpperCase()}</p>
                <p>Decrypted filename: ${result.filename}</p>
                <div class="download-buttons">
                    <button class="btn btn-primary" onclick="downloadDecryptedFile('${result.download_url}', '${result.filename}')">
                        Download Decrypted File
                    </button>
                </div>
            </div>
        `;
        
        // Remove any existing file info
        const existingInfo = form.querySelector('.file-info');
        if (existingInfo) {
            existingInfo.remove();
        }
        
        // Add new file info
        form.appendChild(fileTypeInfo);
        
        // Clear form
        form.reset();
        
        // Reset form state
        submitButton.textContent = originalButtonText;
        submitButton.disabled = false;
        
    } catch (error) {
        console.error('Decryption error:', error);
        showError(error.message);
        
        // Reset button state
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
        submitButton.textContent = 'Decrypt File';
        submitButton.disabled = false;
        }
    }
}

async function downloadDecryptedFile(url, filename) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('Failed to download file');
        }
        
        const blob = await response.blob();
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = filename;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(downloadLink.href);
        
        showSuccess('File downloaded successfully!');
    } catch (error) {
        showError('Failed to download file');
        console.error('Download error:', error);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Sharing functionality removed

function showSuccess(message) {
    const toast = document.createElement('div');
    toast.className = 'toast success';
    toast.textContent = message;
    toast.style.left = '';
    toast.style.transform = '';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'toast error';
    toast.textContent = message || 'An error occurred';
    toast.style.left = '';
    toast.style.transform = '';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

function togglePasswordVisibility(inputId, buttonId) {
    const passwordInput = document.getElementById(inputId);
    const toggleButton = document.getElementById(buttonId);
    const passwordContainer = toggleButton.closest('.password-container');
    
    if (!passwordInput || !toggleButton) return;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleButton.title = 'Hide password';
        
        // Toggle eye icons
        const showIcon = toggleButton.querySelector('.eye-show');
        const hideIcon = toggleButton.querySelector('.eye-hide');
        
        if (showIcon) showIcon.style.display = 'none';
        if (hideIcon) hideIcon.style.display = 'block';
        
        // Add active state to container
        if (passwordContainer) {
            passwordContainer.classList.add('show-password');
            toggleButton.style.backgroundColor = 'rgba(99, 102, 241, 0.08)';
            toggleButton.style.borderLeft = '1px solid var(--input-border)';
        }
    } else {
        passwordInput.type = 'password';
        toggleButton.title = 'Show password';
        
        // Toggle eye icons
        const showIcon = toggleButton.querySelector('.eye-show');
        const hideIcon = toggleButton.querySelector('.eye-hide');
        
        if (showIcon) showIcon.style.display = 'block';
        if (hideIcon) hideIcon.style.display = 'none';
        
        // Remove active state from container
        if (passwordContainer) {
            passwordContainer.classList.remove('show-password');
            toggleButton.style.backgroundColor = '';
            toggleButton.style.borderLeft = '1px solid transparent';
        }
    }
}

// Function to detect encryption method from file
function detectEncryptionMethod(file) {
    // Check if file name or metadata contains information about encryption method
    const fileName = file.name.toLowerCase();
    
    // Show appropriate form fields based on detected method
    const passwordGroup = document.getElementById('decrypt-password-group');
    const keyGroup = document.getElementById('decrypt-key-group');
    const keyPasswordGroup = document.getElementById('decrypt-key-password-group');
    
    if (fileName.includes('sym') || fileName.includes('password')) {
        // Symmetric encryption detected
        if (passwordGroup) passwordGroup.style.display = 'block';
        if (keyGroup) keyGroup.style.display = 'none';
        if (keyPasswordGroup) keyPasswordGroup.style.display = 'none';
    } else if (fileName.includes('asym') || fileName.includes('pubkey')) {
        // Asymmetric encryption detected
        if (passwordGroup) passwordGroup.style.display = 'none';
        if (keyGroup) keyGroup.style.display = 'block';
        if (keyPasswordGroup) {
            const keySelect = document.getElementById('decrypt-key');
            keyPasswordGroup.style.display = keySelect && keySelect.value ? 'block' : 'none';
        }
    } else {
        // Default to showing both options
        if (passwordGroup) passwordGroup.style.display = 'block';
        if (keyGroup) keyGroup.style.display = 'block';
        if (keyPasswordGroup) {
            const keySelect = document.getElementById('decrypt-key');
            keyPasswordGroup.style.display = keySelect && keySelect.value ? 'block' : 'none';
        }
    }
}

// Function to show the create key modal
function showCreateKeyModal() {
    const modal = document.getElementById('create-key-modal');
    if (modal) {
        // Center the modal
        modal.style.display = 'flex';
        modal.style.alignItems = 'center';
        modal.style.justifyContent = 'center';
        
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            // Style modal content
            modalContent.style.margin = '0 auto';
            modalContent.style.width = '100%';
            modalContent.style.maxWidth = '500px';
            modalContent.style.borderRadius = '12px';
            modalContent.style.boxShadow = '0 4px 25px rgba(0, 0, 0, 0.1)';
            modalContent.style.backgroundColor = 'white';
            
            // Style form elements
            const inputs = modalContent.querySelectorAll('input[type="text"], input[type="password"]');
            inputs.forEach(input => {
                input.style.width = '100%';
                input.style.padding = '10px 12px';
                input.style.borderRadius = '6px';
                input.style.border = '1px solid #ddd';
                input.style.boxSizing = 'border-box';
                input.style.fontSize = '16px';
            });
            
            // Style form labels
            const labels = modalContent.querySelectorAll('label');
            labels.forEach(label => {
                label.style.fontWeight = 'bold';
                label.style.marginBottom = '8px';
                label.style.display = 'block';
            });
            
            // Style form groups
            const formGroups = modalContent.querySelectorAll('.form-group');
            formGroups.forEach(group => {
                group.style.marginBottom = '20px';
            });
            
            // Style algorithm options
            const algorithmOptions = modalContent.querySelectorAll('.key-algorithm-option');
            algorithmOptions.forEach(option => {
                option.style.border = '1px solid #e2e8f0';
                option.style.borderRadius = '8px';
                option.style.padding = '16px';
                option.style.marginBottom = '10px';
                option.style.cursor = 'pointer';
                option.style.transition = 'all 0.2s ease';
                
                // Change background when selected
                const radio = option.querySelector('input[type="radio"]');
                if (radio && radio.checked) {
                    option.style.borderColor = '#4f46e5';
                    option.style.backgroundColor = '#f5f3ff';
                }
                
                // Add click event to select the option
                option.addEventListener('click', () => {
                    // Select the radio button
                    const radio = option.querySelector('input[type="radio"]');
                    if (radio) {
                        radio.checked = true;
                        
                        // Update styles of all options
                        algorithmOptions.forEach(opt => {
                            opt.style.borderColor = '#e2e8f0';
                            opt.style.backgroundColor = 'white';
                        });
                        
                        // Highlight selected option
                        option.style.borderColor = '#4f46e5';
                        option.style.backgroundColor = '#f5f3ff';
                    }
                });
            });
            
            // Style algorithm badges
            const badges = modalContent.querySelectorAll('.option-badge');
            badges.forEach(badge => {
                badge.style.fontSize = '12px';
                badge.style.fontWeight = 'bold';
                badge.style.padding = '4px 8px';
                badge.style.borderRadius = '4px';
                
                if (badge.classList.contains('recommended')) {
                    badge.style.backgroundColor = '#ecfdf5';
                    badge.style.color = '#10b981';
                } else if (badge.classList.contains('high-security')) {
                    badge.style.backgroundColor = '#eff6ff';
                    badge.style.color = '#3b82f6';
                }
            });
            
            // Style buttons
            const buttons = modalContent.querySelectorAll('button');
            buttons.forEach(button => {
                button.style.borderRadius = '6px';
                button.style.padding = '10px 16px';
                button.style.fontWeight = 'bold';
                button.style.cursor = 'pointer';
            });
            
            // Style the create button specifically
            const createButton = modalContent.querySelector('.btn-create');
            if (createButton) {
                createButton.style.backgroundColor = '#f59e0b';
                createButton.style.color = 'white';
                createButton.style.border = 'none';
            }
            
            // Style the cancel button
            const cancelButton = modalContent.querySelector('.btn-cancel');
            if (cancelButton) {
                cancelButton.style.backgroundColor = '#f1f5f9';
                cancelButton.style.color = '#64748b';
                cancelButton.style.border = '1px solid #e2e8f0';
            }
            
            // Style the modal header
            const modalHeader = modalContent.querySelector('.modal-header');
            if (modalHeader) {
                modalHeader.style.borderBottom = '1px solid #e2e8f0';
                modalHeader.style.padding = '16px 24px';
                modalHeader.style.display = 'flex';
                modalHeader.style.justifyContent = 'space-between';
                modalHeader.style.alignItems = 'center';
            }
            
            // Style the modal actions
            const modalActions = modalContent.querySelector('.modal-actions');
            if (modalActions) {
                modalActions.style.display = 'flex';
                modalActions.style.justifyContent = 'flex-end';
                modalActions.style.gap = '12px';
                modalActions.style.padding = '16px 24px';
                modalActions.style.borderTop = '1px solid #e2e8f0';
            }
            
            // Style password container
            const passwordContainer = modalContent.querySelector('.password-container');
            if (passwordContainer) {
                passwordContainer.style.position = 'relative';
                passwordContainer.style.display = 'flex';
                passwordContainer.style.alignItems = 'center';
                
                const passwordInput = passwordContainer.querySelector('input[type="password"]');
                if (passwordInput) {
                    passwordInput.style.width = '100%';
                    passwordInput.style.paddingRight = '40px'; // Space for the toggle button
                }
                
                const toggleButton = passwordContainer.querySelector('.password-toggle');
                if (toggleButton) {
                    toggleButton.style.position = 'absolute';
                    toggleButton.style.right = '10px';
                    toggleButton.style.background = 'none';
                    toggleButton.style.border = 'none';
                    toggleButton.style.cursor = 'pointer';
                    toggleButton.style.color = '#6b7280';
                }
            }
            
            // Style the help text
            const helpText = modalContent.querySelectorAll('.help-text');
            helpText.forEach(text => {
                text.style.fontSize = '12px';
                text.style.color = '#6b7280';
                text.style.marginTop = '4px';
            });
        }
    }
}

// Function to close modals
function closeModal() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
        
        // Reset modal content styles when closing to avoid conflicts next time
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            // We maintain the margin auto but reset all other styles
            modalContent.style.margin = '0 auto';
            modalContent.style.width = '';
            modalContent.style.maxWidth = '';
            modalContent.style.borderRadius = '';
            modalContent.style.boxShadow = '';
        }
    });
}
