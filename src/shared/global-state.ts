/**
 * Global state shared across all securex services
 * Prevents console spam and other shared behaviors
 */

// Single source of truth for security warning state
export let SECURITY_WARNING_SHOWN = false;

export function markSecurityWarningAsShown(): void {
    SECURITY_WARNING_SHOWN = true;
}

export function shouldShowSecurityWarning(): boolean {
    // Only show in development mode and if not already shown
    const isDevelopment = typeof process !== 'undefined' &&
        process.env &&
        process.env.NODE_ENV !== 'production';

    return isDevelopment && !SECURITY_WARNING_SHOWN;
}
