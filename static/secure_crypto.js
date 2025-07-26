// ABOUTME: Secure cryptographic operations using WebAuthn challenge-response system
// ABOUTME: Provides enterprise-grade encryption with true zero-knowledge architecture

// WebAuthn challenge-response cryptographic operations
class SecureCrypto {
    constructor() {
        this.currentCredentialId = null;
    }

    async setCredential(credentialId) {
        this.currentCredentialId = credentialId;
    }

    // Request a challenge for a specific operation
    async requestChallenge(operationType) {
        const response = await fetch('/crypto/challenge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                operation_type: operationType
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to request challenge: ${response.statusText}`);
        }

        return await response.json();
    }

    // Sign a challenge using WebAuthn
    async signChallenge(challengeBytes) {
        if (!this.currentCredentialId) {
            throw new Error('No credential ID set. Please authenticate first.');
        }

        console.log('🔐 SecureCrypto.signChallenge() called');
        console.log('📋 Current credential ID:', this.currentCredentialId ? '[PRESENT]' : '[MISSING]');
        console.log('📏 Credential ID length:', this.currentCredentialId?.length || 0);

        try {
            console.log('🔄 Converting credential ID from base64 to ArrayBuffer');
            const credentialArrayBuffer = this.base64ToArrayBuffer(this.currentCredentialId);
            console.log('✅ Conversion successful, ArrayBuffer length:', credentialArrayBuffer.byteLength);

            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array(challengeBytes),
                    allowCredentials: [{
                        type: 'public-key',
                        id: credentialArrayBuffer
                    }],
                    userVerification: 'preferred',
                    timeout: 60000
                }
            });

            return {
                signature: Array.from(new Uint8Array(assertion.response.signature)),
                authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
                clientDataJSON: Array.from(new Uint8Array(assertion.response.clientDataJSON))
            };
        } catch (error) {
            console.error('WebAuthn signature failed:', error);
            throw new Error('Failed to sign challenge with WebAuthn. Please try again.');
        }
    }

    // Secure file creation with challenge-response
    async createFileSecure(filename, tags, content) {
        try {
            // Step 1: Request challenge
            const challenge = await this.requestChallenge('file_create');

            // Step 2: Sign challenge
            const signature = await this.signChallenge(challenge.challenge_bytes);

            // Step 3: Create file with signed challenge
            const response = await fetch('/crypto/files/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    filename,
                    tags,
                    content,
                    challenge_id: challenge.challenge_id,
                    webauthn_signature: signature.signature
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to create file: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Secure file creation failed:', error);
            throw error;
        }
    }

    // Secure file content retrieval with challenge-response
    async getFileContentSecure(fileId, versionId = null) {
        try {
            // Step 1: Request challenge
            const challenge = await this.requestChallenge('file_read');

            // Step 2: Sign challenge
            const signature = await this.signChallenge(challenge.challenge_bytes);

            // Step 3: Get file content with signed challenge
            const response = await fetch(`/crypto/files/${fileId}/content`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    version_id: versionId,
                    challenge_id: challenge.challenge_id,
                    webauthn_signature: signature.signature
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to get file content: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Secure file retrieval failed:', error);
            throw error;
        }
    }

    // Secure file version saving with challenge-response
    async saveFileVersionSecure(fileId, content, changeSummary = null) {
        try {
            // Step 1: Request challenge
            const challenge = await this.requestChallenge('file_write');

            // Step 2: Sign challenge
            const signature = await this.signChallenge(challenge.challenge_bytes);

            // Step 3: Save file version with signed challenge
            const response = await fetch(`/crypto/files/${fileId}/save`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    content,
                    change_summary: changeSummary,
                    challenge_id: challenge.challenge_id,
                    webauthn_signature: signature.signature
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to save file: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Secure file saving failed:', error);
            throw error;
        }
    }

    // Utility function to convert base64url to ArrayBuffer
    base64urlToArrayBuffer(base64url) {
        // Convert base64url to base64
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        // Convert to ArrayBuffer
        const binaryString = atob(padded);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Utility function to convert standard base64 to ArrayBuffer
    base64ToArrayBuffer(base64) {
        // Add padding if needed
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        // Convert to ArrayBuffer
        const binaryString = atob(padded);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Utility function to convert ArrayBuffer to base64url
    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
}

// Global instance
window.secureCrypto = new SecureCrypto();

// Expose for debugging in dev mode
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.debugSecureCrypto = window.secureCrypto;
}
