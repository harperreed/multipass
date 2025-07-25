// ABOUTME: Client-side authentication utilities for cookie-based session management
// ABOUTME: Replaces localStorage token handling with secure HttpOnly cookie authentication

// Check if user is authenticated by making a test API call
async function checkAuthentication() {
    try {
        const response = await fetch('/files', {
            method: 'GET',
            credentials: 'same-origin' // Include cookies
        });
        return response.ok;
    } catch (error) {
        console.error('Authentication check failed:', error);
        return false;
    }
}

// Logout function that calls the server logout endpoint
async function logout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            credentials: 'same-origin' // Include cookies
        });

        if (response.ok) {
            // Redirect to login page
            window.location.href = '/';
            return true;
        } else {
            console.error('Logout failed');
            return false;
        }
    } catch (error) {
        console.error('Logout error:', error);
        return false;
    }
}

// Utility to make authenticated API calls
async function authenticatedFetch(url, options = {}) {
    const defaultOptions = {
        credentials: 'same-origin', // Always include cookies
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    };

    const mergedOptions = { ...defaultOptions, ...options };

    try {
        const response = await fetch(url, mergedOptions);

        // If we get a 401, redirect to login
        if (response.status === 401) {
            window.location.href = '/';
            return null;
        }

        return response;
    } catch (error) {
        console.error('Authenticated fetch error:', error);
        throw error;
    }
}

// Replace the legacy localStorage-based session management
function redirectToLoginIfNotAuthenticated() {
    checkAuthentication().then(isAuthenticated => {
        if (!isAuthenticated) {
            window.location.href = '/';
        }
    });
}

// Initialize authentication check on page load for protected pages
if (window.location.pathname !== '/') {
    redirectToLoginIfNotAuthenticated();
}
