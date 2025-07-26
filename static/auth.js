// ABOUTME: Authentication management for MultiPass using WebAuthn
// ABOUTME: Handles login, registration, and credential management

class Auth {
    static async checkAuthStatus() {
        console.log('🔍 Auth.checkAuthStatus() called');

        // Check if we have stored credentials
        const passkeyId = localStorage.getItem('passkey_id');
        console.log('📋 Stored passkey_id:', passkeyId ? '[PRESENT]' : '[MISSING]');

        if (!passkeyId) {
            console.log('❌ No passkey_id in localStorage - returning unauthenticated');
            return { authenticated: false };
        }

        // Verify server session is still valid by making a test request
        console.log('🌐 Making auth check request to /files');
        try {
            const response = await fetch('/files', {
                method: 'GET',
                credentials: 'include'
            });

            console.log('📡 Auth check response:', {
                status: response.status,
                statusText: response.statusText,
                ok: response.ok
            });

            if (response.ok) {
                console.log('✅ Auth check successful - session valid');
                // Set credentials in app
                if (window.app) {
                    window.app.setCredentials(passkeyId);
                    console.log('📱 Set credentials in app');
                }
                const data = await response.json();
                console.log('📁 Files data received:', data.files?.length || 0, 'files');
                return { authenticated: true, filesData: data };
            } else if (response.status === 401) {
                console.log('🔒 Session expired (401) - clearing localStorage');
                // Session expired, clear localStorage
                localStorage.removeItem('passkey_id');
                return { authenticated: false };
            } else {
                console.log('⚠️ Other error but assuming session valid:', response.status);
                // Other error, but session might be valid
                if (window.app) {
                    window.app.setCredentials(passkeyId);
                }
                return { authenticated: true };
            }
        } catch (error) {
            console.error('💥 Auth check failed with error:', error);
            // Network error - assume session is still valid if we have stored credentials
            if (window.app) {
                window.app.setCredentials(passkeyId);
            }
            return { authenticated: true };
        }
    }

    static async startRegistration(username, displayName) {
        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    username,
                    display_name: displayName
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `Registration failed: ${response.statusText}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Registration start error:', error);
            throw error;
        }
    }

    static async finishRegistration(userId, credential, vaultName) {
        console.log('🎯 Auth.finishRegistration() called', { userId, vaultName });

        try {
            console.log('🌐 Sending registration finish request');
            const response = await fetch('/register/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    user_id: userId,
                    credential,
                    vault_name: vaultName
                })
            });

            console.log('📡 Registration finish response:', {
                status: response.status,
                statusText: response.statusText,
                ok: response.ok
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                console.error('❌ Registration finish failed:', errorData);
                throw new Error(errorData.message || `Registration completion failed: ${response.statusText}`);
            }

            const data = await response.json();
            console.log('✅ Registration finish successful:', data);

            // Store credentials
            if (data.passkey_id) {
                console.log('💾 Storing passkey_id in localStorage:', data.passkey_id);
                localStorage.setItem('passkey_id', data.passkey_id);
                if (window.app) {
                    window.app.setCredentials(data.passkey_id);
                    console.log('📱 Set credentials in app');
                }
            } else {
                console.warn('⚠️ No passkey_id in registration response');
            }

            return data;
        } catch (error) {
            console.error('💥 Registration finish error:', error);
            throw error;
        }
    }

    static async startAuthentication(username) {
        try {
            const response = await fetch('/authenticate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `Authentication failed: ${response.statusText}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Authentication start error:', error);
            throw error;
        }
    }

    static async finishAuthentication(credential) {
        try {
            const response = await fetch('/authenticate/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ credential })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `Authentication completion failed: ${response.statusText}`);
            }

            const data = await response.json();

            // Store credentials
            if (data.passkey_id) {
                localStorage.setItem('passkey_id', data.passkey_id);
                if (window.app) {
                    window.app.setCredentials(data.passkey_id);
                }
            }

            return data;
        } catch (error) {
            console.error('Authentication finish error:', error);
            throw error;
        }
    }

    static async logout() {
        try {
            await fetch('/logout', {
                method: 'POST',
                credentials: 'include'
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            // Always clear local storage and redirect
            localStorage.removeItem('passkey_id');
            localStorage.removeItem('current_file_id');
            localStorage.removeItem('current_file_name');
            window.location.href = '/';
        }
    }

    // WebAuthn utility functions
    static arrayBufferToBase64url(buffer) {
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

    static base64urlToArrayBuffer(base64url) {
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

    // Convert WebAuthn response for transmission
    static encodeWebAuthnResponse(response) {
        const encoded = {
            id: response.id,
            rawId: this.arrayBufferToBase64url(response.rawId),
            type: response.type,
            response: {}
        };

        if (response.response.clientDataJSON) {
            encoded.response.clientDataJSON = this.arrayBufferToBase64url(response.response.clientDataJSON);
        }

        if (response.response.attestationObject) {
            // Registration response
            encoded.response.attestationObject = this.arrayBufferToBase64url(response.response.attestationObject);
        }

        if (response.response.authenticatorData) {
            // Authentication response
            encoded.response.authenticatorData = this.arrayBufferToBase64url(response.response.authenticatorData);
            encoded.response.signature = this.arrayBufferToBase64url(response.response.signature);

            if (response.response.userHandle) {
                encoded.response.userHandle = this.arrayBufferToBase64url(response.response.userHandle);
            }
        }

        return encoded;
    }

    // Convert server challenge data for WebAuthn
    static decodeWebAuthnChallenge(serverData) {
        const decoded = { ...serverData };

        if (decoded.challenge) {
            decoded.challenge = this.base64urlToArrayBuffer(decoded.challenge);
        }

        if (decoded.allowCredentials) {
            decoded.allowCredentials = decoded.allowCredentials.map(cred => ({
                ...cred,
                id: this.base64urlToArrayBuffer(cred.id)
            }));
        }

        if (decoded.excludeCredentials) {
            decoded.excludeCredentials = decoded.excludeCredentials.map(cred => ({
                ...cred,
                id: this.base64urlToArrayBuffer(cred.id)
            }));
        }

        if (decoded.user && decoded.user.id) {
            decoded.user.id = this.base64urlToArrayBuffer(decoded.user.id);
        }

        return decoded;
    }
}

// Make Auth globally available
window.Auth = Auth;
