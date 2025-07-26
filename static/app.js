// ABOUTME: Main application JavaScript for MultiPass file browser
// ABOUTME: Coordinates secure file operations, authentication, and UI interactions

class MultiPassApp {
    constructor() {
        this.currentPasskeyId = null;
        this.files = [];
        this.filteredFiles = [];
        this.searchTerm = '';
        this.selectedTag = '';

        // Initialize secure crypto when available
        if (window.secureCrypto) {
            this.secureCrypto = window.secureCrypto;
        }
    }

    // Authentication methods
    setCredentials(passkeyId) {
        this.currentPasskeyId = passkeyId;
        localStorage.setItem('passkey_id', passkeyId);

        if (this.secureCrypto) {
            this.secureCrypto.setCredential(passkeyId);
        }
    }

    async checkAuthentication() {
        console.log('🔐 MultiPassApp.checkAuthentication() called');
        const storedPasskeyId = localStorage.getItem('passkey_id');
        console.log('📋 Stored passkey_id:', storedPasskeyId ? '[PRESENT]' : '[MISSING]');

        if (storedPasskeyId) {
            console.log('✅ Setting credentials from stored passkey_id');
            this.setCredentials(storedPasskeyId);
            return true;
        }
        console.log('❌ No stored credentials found');
        return false;
    }

    // File operations using secure crypto
    async loadFiles() {
        console.log('📁 MultiPassApp.loadFiles() called');
        console.log('🔑 Current passkey_id:', this.currentPasskeyId ? '[PRESENT]' : '[MISSING]');

        if (!this.currentPasskeyId) {
            console.error('❌ No passkey ID available - cannot load files');
            return;
        }

        try {
            console.log('🌐 Making request to /files endpoint');
            const response = await fetch('/files', {
                method: 'GET',
                credentials: 'include'
            });

            console.log('📡 Files response:', {
                status: response.status,
                statusText: response.statusText,
                ok: response.ok
            });

            if (!response.ok) {
                throw new Error(`Failed to load files: ${response.statusText}`);
            }

            const data = await response.json();
            this.files = data.files;
            this.filterFiles();
        } catch (error) {
            console.error('Error loading files:', error);
            UI.showToast('Error', 'Failed to load files', 'error');
        }
    }

    async createFile(filename, tags, content) {
        if (!this.currentPasskeyId) {
            UI.showToast('Error', 'Please authenticate first', 'error');
            return;
        }

        if (!this.secureCrypto) {
            UI.showToast('Error', 'Secure crypto not available', 'error');
            return;
        }

        try {
            UI.showToast('Creating', 'Creating file securely...');

            const result = await this.secureCrypto.createFileSecure(
                filename,
                tags || '',
                content || ''
            );

            UI.showToast('Success', 'File created successfully', 'success');
            await this.loadFiles(); // Refresh file list
            return result;
        } catch (error) {
            console.error('Error creating file:', error);
            UI.showToast('Error', error.message || 'Failed to create file', 'error');
            throw error;
        }
    }

    async getFileContent(fileId, versionId = null) {
        if (!this.secureCrypto) {
            UI.showToast('Error', 'Secure crypto not available', 'error');
            return null;
        }

        try {
            return await this.secureCrypto.getFileContentSecure(fileId, versionId);
        } catch (error) {
            console.error('Error getting file content:', error);
            UI.showToast('Error', error.message || 'Failed to get file content', 'error');
            throw error;
        }
    }

    async saveFileVersion(fileId, content, changeSummary = null) {
        if (!this.secureCrypto) {
            UI.showToast('Error', 'Secure crypto not available', 'error');
            return null;
        }

        try {
            UI.showToast('Saving', 'Saving file securely...');

            const result = await this.secureCrypto.saveFileVersionSecure(
                fileId,
                content,
                changeSummary
            );

            UI.showToast('Success', 'File saved successfully', 'success');
            return result;
        } catch (error) {
            console.error('Error saving file:', error);
            UI.showToast('Error', error.message || 'Failed to save file', 'error');
            throw error;
        }
    }

    async deleteFile(fileId, filename) {
        if (!this.currentPasskeyId) {
            UI.showToast('Error', 'Please authenticate first', 'error');
            return;
        }

        if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await fetch(`/files/${fileId}/delete`, {
                method: 'DELETE',
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`Failed to delete file: ${response.statusText}`);
            }

            UI.showToast('Success', 'File deleted successfully', 'success');
            await this.loadFiles(); // Refresh file list
        } catch (error) {
            console.error('Error deleting file:', error);
            UI.showToast('Error', error.message || 'Failed to delete file', 'error');
        }
    }

    // File filtering and search
    filterFiles() {
        this.filteredFiles = this.files.filter(file => {
            const matchesSearch = !this.searchTerm ||
                file.filename.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
                file.tags.toLowerCase().includes(this.searchTerm.toLowerCase());

            const matchesTag = !this.selectedTag ||
                file.tags.toLowerCase().includes(this.selectedTag.toLowerCase());

            return matchesSearch && matchesTag;
        });

        UI.renderFiles(this.filteredFiles, this.searchTerm);
        UI.renderTagCloud(this.files, this.selectedTag);
    }

    setSearchTerm(term) {
        this.searchTerm = term;
        this.filterFiles();
    }

    setSelectedTag(tag) {
        this.selectedTag = tag;
        this.filterFiles();
    }

    // Navigation
    openFile(fileId, filename) {
        localStorage.setItem('current_file_id', fileId);
        localStorage.setItem('current_file_name', filename);
        window.location.href = '/editor.html';
    }

    // Authentication
    async logout() {
        try {
            await fetch('/logout', {
                method: 'POST',
                credentials: 'include'
            });

            // Clear local storage
            localStorage.removeItem('passkey_id');
            localStorage.removeItem('current_file_id');
            localStorage.removeItem('current_file_name');

            // Redirect to login
            window.location.href = '/';
        } catch (error) {
            console.error('Logout error:', error);
            // Still redirect even if logout request fails
            window.location.href = '/';
        }
    }
}

// Global app instance
window.app = new MultiPassApp();
