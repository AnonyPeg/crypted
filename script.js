class Crypted {
    constructor() {
        this.files = [];
        this.isDecryptionMode = false;
        this.initializeEventListeners();
        this.updateUIForMode();
    }

    initializeEventListeners() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const passwordInput = document.getElementById('passwordInput');
        const togglePassword = document.getElementById('togglePassword');
        const actionBtn = document.getElementById('actionBtn');
        const faqBtn = document.getElementById('faqBtn');
        const closeFaq = document.getElementById('closeFaq');
        const faqPopup = document.getElementById('faqPopup');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            this.handleFiles(e.dataTransfer.files);
        });

        fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files);
        });

        togglePassword.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            togglePassword.innerHTML = type === 'password' ? 
                '<i class="fas fa-eye"></i>' : 
                '<i class="fas fa-eye-slash"></i>';
        });

        passwordInput.addEventListener('input', (e) => {
            this.updateSecurityLevel(e.target.value);
        });

        actionBtn.addEventListener('click', () => {
            if (this.isDecryptionMode) {
                this.decryptFiles();
            } else {
                this.encryptFiles();
            }
        });

        faqBtn.addEventListener('click', () => {
            faqPopup.style.display = 'flex';
        });

        closeFaq.addEventListener('click', () => {
            faqPopup.style.display = 'none';
        });

        faqPopup.addEventListener('click', (e) => {
            if (e.target === faqPopup) {
                faqPopup.style.display = 'none';
            }
        });

        const faqQuestions = document.querySelectorAll('.faq-question');
        faqQuestions.forEach(question => {
            question.addEventListener('click', () => {
                this.toggleFAQ(question);
            });
        });
    }

    handleFiles(fileList) {
        this.files = Array.from(fileList);
        
        const hasEncryptedFiles = this.files.some(file => 
            file.name.toLowerCase().endsWith('.encrypted')
        );
        
        if (hasEncryptedFiles && !this.isDecryptionMode) {
            this.isDecryptionMode = true;
            this.updateUIForMode();
        } else if (!hasEncryptedFiles && this.isDecryptionMode) {
            this.isDecryptionMode = false;
            this.updateUIForMode();
        }
        
        this.updateFileList();
    }

    updateUIForMode() {
        const modeIndicator = document.getElementById('modeIndicator');
        const uploadTitle = document.getElementById('uploadTitle');
        const uploadSubtitle = document.getElementById('uploadSubtitle');
        const passwordTitle = document.getElementById('passwordTitle');
        const actionText = document.getElementById('actionText');
        const actionIcon = document.getElementById('actionIcon');

        if (this.isDecryptionMode) {
            modeIndicator.innerHTML = '<i class="fas fa-unlock"></i><span id="modeText">Decryption Mode</span>';
            uploadTitle.textContent = 'Drop encrypted files here to decrypt';
            uploadSubtitle.textContent = 'or click to select .encrypted files';
            passwordTitle.textContent = 'Enter Decryption Password';
            actionText.textContent = 'Decrypt Files';
            actionIcon.className = 'fas fa-unlock';
        } else {
            modeIndicator.innerHTML = '<i class="fas fa-lock"></i><span id="modeText">Encryption Mode</span>';
            uploadTitle.textContent = 'Drop files here to encrypt';
            uploadSubtitle.textContent = 'or click to select files';
            passwordTitle.textContent = 'Set Encryption Password';
            actionText.textContent = 'Encrypt Files';
            actionIcon.className = 'fas fa-lock';
        }
    }

    updateFileList() {
        const fileList = document.getElementById('fileList');
        fileList.innerHTML = '';

        this.files.forEach((file, index) => {
            const isEncrypted = file.name.toLowerCase().endsWith('.encrypted');
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-icon">
                    <i class="fas fa-file${isEncrypted ? '-export' : ''}"></i>
                </div>
                <div class="file-info">
                    <div class="file-name">
                        ${file.name}
                        ${isEncrypted ? '<span class="encrypted-badge"><i class="fas fa-lock"></i> Encrypted</span>' : ''}
                    </div>
                    <div class="file-size">${this.formatFileSize(file.size)}</div>
                </div>
                <button class="file-remove" onclick="crypted.removeFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            `;
            fileList.appendChild(fileItem);
        });
    }

    removeFile(index) {
        this.files.splice(index, 1);
        this.updateFileList();
        
        if (this.files.length === 0) {
            this.isDecryptionMode = false;
            this.updateUIForMode();
        }
    }

    updateSecurityLevel(password) {
        const levelFill = document.getElementById('levelFill');
        const labels = ['labelLow', 'labelMedium', 'labelHigh'];
        
        labels.forEach(label => {
            document.getElementById(label).classList.remove('level-active');
        });

        let strength = 0;
        if (password.length >= 12) strength += 1;
        if (password.length >= 16) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;

        levelFill.className = 'level-fill';
        let activeLabel = 'labelLow';

        if (strength <= 2) {
            levelFill.classList.add('level-low');
            activeLabel = 'labelLow';
        } else if (strength <= 4) {
            levelFill.classList.add('level-medium');
            activeLabel = 'labelMedium';
        } else {
            levelFill.classList.add('level-high');
            activeLabel = 'labelHigh';
        }

        document.getElementById(activeLabel).classList.add('level-active');
    }

    async encryptFiles() {
        const password = document.getElementById('passwordInput').value;
        if (!this.validatePassword(password)) return;

        if (this.files.length === 0) {
            this.showStatus('Please select files to encrypt', 0);
            return;
        }

        this.showStatus('Starting encryption...', 0);

        try {
            for (let i = 0; i < this.files.length; i++) {
                const file = this.files[i];
                const progress = ((i + 1) / this.files.length) * 100;
                this.showStatus(`Encrypting: ${file.name}`, progress);
                
                await new Promise(resolve => setTimeout(resolve, 300));
                
                const encryptedData = await this.encryptFile(file, password);
                this.downloadFile(encryptedData, file.name + '.encrypted');
            }

            this.showStatus('All files encrypted successfully!', 100);
            setTimeout(() => {
                this.hideStatus();
                this.files = [];
                this.updateFileList();
            }, 2000);

        } catch (error) {
            this.showStatus(`Encryption failed: ${error.message}`, 0);
        }
    }

    async decryptFiles() {
        const password = document.getElementById('passwordInput').value;
        if (!this.validatePassword(password)) return;

        if (this.files.length === 0) {
            this.showStatus('Please select encrypted files to decrypt', 0);
            return;
        }

        this.showStatus('Starting decryption...', 0);

        try {
            for (let i = 0; i < this.files.length; i++) {
                const file = this.files[i];
                const progress = ((i + 1) / this.files.length) * 100;
                this.showStatus(`Decrypting: ${file.name}`, progress);
                
                await new Promise(resolve => setTimeout(resolve, 300));
                
                const arrayBuffer = await this.readFileAsArrayBuffer(file);
                const decryptedData = await this.decryptData(arrayBuffer, password);
                const originalName = file.name.replace('.encrypted', '');
                this.downloadFile(decryptedData, originalName);
            }

            this.showStatus('All files decrypted successfully!', 100);
            setTimeout(() => {
                this.hideStatus();
                this.files = [];
                this.updateFileList();
                this.isDecryptionMode = false;
                this.updateUIForMode();
            }, 2000);

        } catch (error) {
            this.showStatus(`Decryption failed: ${error.message}`, 0);
        }
    }

    validatePassword(password) {
        if (!password) {
            this.showStatus('Please enter a password', 0);
            return false;
        }
        if (password.length < 12) {
            this.showStatus('Password must be at least 12 characters', 0);
            return false;
        }
        return true;
    }

    async encryptFile(file, password) {
        try {
            const fileData = await this.readFileAsArrayBuffer(file);
            
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const iterations = 200000;
            
            const key = await this.deriveKey(password, salt, iterations);
            
            const encryptedContent = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                fileData
            );

            const MAGIC = new TextEncoder().encode('CRYPTED1');
            const version = new Uint8Array([1]);
            const iterBuf = new Uint8Array(new Uint32Array([iterations]).buffer);

            const result = new Uint8Array(
                MAGIC.length + version.length + iterBuf.length + salt.length + iv.length + encryptedContent.byteLength
            );

            let offset = 0;
            result.set(MAGIC, offset); offset += MAGIC.length;
            result.set(version, offset); offset += version.length;
            result.set(iterBuf, offset); offset += iterBuf.length;
            result.set(salt, offset); offset += salt.length;
            result.set(iv, offset); offset += iv.length;
            result.set(new Uint8Array(encryptedContent), offset);

            return result;

        } catch (error) {
            throw new Error('Encryption failed');
        }
    }

    async decryptData(encryptedData, password) {
        try {
            const encryptedArray = new Uint8Array(encryptedData);
            
            const MAGIC = new TextEncoder().encode('CRYPTED1');
            const magicFromFile = encryptedArray.slice(0, MAGIC.length);
            
            if (this.arrayBufferToHex(magicFromFile) !== this.arrayBufferToHex(MAGIC)) {
                throw new Error('Invalid file format');
            }
            
            let offset = MAGIC.length;
            const version = encryptedArray.slice(offset, offset + 1); offset += 1;
            const iterBuf = encryptedArray.slice(offset, offset + 4); offset += 4;
            const iterations = new Uint32Array(iterBuf.buffer)[0];
            const salt = encryptedArray.slice(offset, offset + 16); offset += 16;
            const iv = encryptedArray.slice(offset, offset + 12); offset += 12;
            const content = encryptedArray.slice(offset);
            
            const key = await this.deriveKey(password, salt, iterations);
            
            const decryptedContent = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                content
            );

            return decryptedContent;

        } catch (error) {
            throw new Error('Wrong password or corrupted file');
        }
    }

    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async deriveKey(password, salt, iterations = 200000) {
        const encoder = new TextEncoder();
        const normalized = password.normalize('NFKC');
        const passwordBuffer = encoder.encode(normalized);

        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsArrayBuffer(file);
        });
    }

    downloadFile(data, filename) {
        const blob = new Blob([data], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    showStatus(message, progress) {
        const statusArea = document.getElementById('statusArea');
        const statusText = document.getElementById('statusText');
        const progressFill = document.getElementById('progressFill');
        
        statusArea.style.display = 'block';
        statusText.textContent = message;
        progressFill.style.width = progress + '%';
    }

    hideStatus() {
        const statusArea = document.getElementById('statusArea');
        statusArea.style.display = 'none';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    toggleFAQ(element) {
        const faqItem = element.parentElement;
        faqItem.classList.toggle('active');
    }
}

const crypted = new Crypted();