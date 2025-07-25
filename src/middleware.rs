// ABOUTME: Security middleware for Content-Security-Policy and other HTTP headers
// ABOUTME: Provides protection against XSS, clickjacking, and other common web vulnerabilities

use axum::{
    body::Body,
    http::{HeaderValue, Request, header},
    middleware::Next,
    response::Response,
};

pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Content Security Policy - restrictive policy for enhanced security
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; \
             font-src 'self' https://fonts.gstatic.com; \
             img-src 'self' data:; \
             connect-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );

    // Prevent clickjacking
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );

    // Prevent MIME type sniffing
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // Enable XSS protection
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );

    // Strict Transport Security (for HTTPS)
    headers.insert(
        header::HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    response
}
