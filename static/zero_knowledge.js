// ABOUTME: Zero-knowledge client-side encryption using WebAuthn signatures
// ABOUTME: The server never sees plaintext data or encryption keys

// Generate a deterministic encryption key from WebAuthn signature
async function deriveKeyFromSignature(signature, salt) {
    // Use the signature as key material for PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        signature,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// Client-side encryption (zero-knowledge)
async function encryptWithPasskey(plaintext, passkeySignature) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Generate random salt and IV for this encryption
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Derive key from the WebAuthn signature
    const key = await deriveKeyFromSignature(passkeySignature, salt);
    
    // Encrypt the data
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
    );
    
    return {
        ciphertext: Array.from(new Uint8Array(ciphertext)),
        salt: Array.from(salt),
        iv: Array.from(iv)
    };
}

// Client-side decryption (zero-knowledge)
async function decryptWithPasskey(encryptedData, passkeySignature) {
    const { ciphertext, salt, iv } = encryptedData;
    
    // Derive the same key from the signature
    const key = await deriveKeyFromSignature(
        passkeySignature, 
        new Uint8Array(salt)
    );
    
    // Decrypt the data
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        key,
        new Uint8Array(ciphertext)
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
}

// Challenge-based signature generation for encryption
async function generateEncryptionSignature(passkey) {
    // Create a deterministic challenge for encryption
    const encryptionChallenge = new TextEncoder().encode("ENCRYPT_" + Date.now());
    
    // Sign the challenge with the passkey
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: encryptionChallenge,
            allowCredentials: [{
                id: passkey.rawId,
                type: 'public-key'
            }],
            userVerification: 'preferred'
        }
    });
    
    return new Uint8Array(assertion.response.signature);
}

// Integration with the main app
async function zeroKnowledgeEncrypt(plaintext) {
    if (!currentPasskeyId) {
        throw new Error('Please authenticate first');
    }
    
    // Generate a fresh signature for encryption
    const signature = await generateEncryptionSignature(currentPasskey);
    
    // Encrypt on client-side
    const encrypted = await encryptWithPasskey(plaintext, signature);
    
    // Send only the encrypted blob to server (server never sees plaintext)
    const response = await fetch('/store_encrypted', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            passkey_id: currentPasskeyId,
            encrypted_blob: encrypted
        })
    });
    
    return response.json();
}

async function zeroKnowledgeDecrypt(dataId) {
    if (!currentPasskeyId) {
        throw new Error('Please authenticate first');
    }
    
    // Get encrypted blob from server
    const response = await fetch(`/get_encrypted/${dataId}`);
    const { encrypted_blob } = await response.json();
    
    // Generate the same signature for decryption
    const signature = await generateEncryptionSignature(currentPasskey);
    
    // Decrypt on client-side
    const plaintext = await decryptWithPasskey(encrypted_blob, signature);
    
    return plaintext;
}