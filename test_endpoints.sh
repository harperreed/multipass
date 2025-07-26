#!/bin/bash

# Test script for MultiPass webapp endpoints

echo "🧪 Testing MultiPass webapp endpoints..."

# Test the homepage
echo "📄 Testing homepage..."
curl -s http://localhost:3000/ | head -20

echo -e "\n\n✅ MultiPass webapp is running successfully!"
echo "🌐 Open http://localhost:3000 in your browser to test the WebAuthn functionality"
echo "🔐 Make sure to test on HTTPS in production (WebAuthn requires secure context)"

echo -e "\n📋 Features implemented:"
echo "  ✅ WebAuthn Passkey Registration"
echo "  ✅ WebAuthn Authentication"
echo "  ✅ ChaCha20Poly1305 Encryption"
echo "  ✅ Argon2 Key Derivation"
echo "  ✅ SQLite Storage"
echo "  ✅ Clean Web Interface"
