/*
  Nera VPN™ - Blind Token Authentication
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  
  This module handles the anonymous token redemption flow:
  1. Generate blinded token in Rust
  2. Send to API with payment code
  3. Unblind the signature in Rust
  4. Save the access token
*/

import { invoke } from '@tauri-apps/api/core';

const API_BASE = 'http://45.76.106.63:3000/api';

/**
 * Redeems a subscription code for an anonymous access token.
 * 
 * @param {string} paymentCode - The subscription code (e.g., "XXXX-XXXX-XXXX")
 * @param {function} onStatusChange - Callback for status updates
 * @returns {Promise<string>} The access token
 */
export async function redeemSubscription(paymentCode, onStatusChange = () => { }) {
    try {
        // --- MOCK MODE ---
        if (paymentCode === 'TEST-CODE-1234') {
            console.log("🛠️ Mock Mode Triggered");
            onStatusChange('Generating secure keys (Mock)...');
            // We still generate a real blinded token to test Rust calc
            const { blinded_token } = await invoke('create_blind_token');
            await new Promise(r => setTimeout(r, 800)); // Fake delay

            onStatusChange('Verifying subscription (Mock)...');
            await new Promise(r => setTimeout(r, 800)); // Fake network delay

            // Use the blinded token itself as the "signature" for simplicity
            const mockSignature = blinded_token;

            onStatusChange('Finalizing authentication (Mock)...');
            // We call unblind just to test the Rust command flow don't crash
            const accessToken = await invoke('unblind_signature', {
                signedBlinded: mockSignature,
            });

            onStatusChange('Saving credentials (Mock)...');
            await invoke('save_access_token', { token: "MOCK-ACCESS-TOKEN-" + Date.now() });

            onStatusChange('Success!');
            return "MOCK-ACCESS-TOKEN";
        }
        // -----------------

        // Step 1: Generate blinded token in Rust
        onStatusChange('Generating secure keys...');
        const { blinded_token } = await invoke('create_blind_token');

        // Step 2: Send to API for signing
        onStatusChange('Verifying subscription...');
        const response = await fetch(`${API_BASE}/auth/redeem`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                blinded_token: blinded_token,
                payment_code: paymentCode.toUpperCase().trim(),
            }),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `Server error: ${response.status}`);
        }

        const data = await response.json();

        if (!data.signed_blinded_token) {
            throw new Error('Invalid server response: missing signature');
        }

        // Step 3: Unblind the signature in Rust
        onStatusChange('Finalizing authentication...');
        const accessToken = await invoke('unblind_signature', {
            signedBlinded: data.signed_blinded_token,
        });

        // Step 4: Save the token
        onStatusChange('Saving credentials...');
        await invoke('save_access_token', { token: accessToken });

        onStatusChange('Success!');
        return accessToken;

    } catch (error) {
        console.error('Redemption failed:', error);
        throw error;
    }
}

/**
 * Checks if user has a valid access token.
 * @returns {Promise<string|null>} The token if exists, null otherwise
 */
export async function getStoredToken() {
    try {
        return await invoke('get_access_token');
    } catch (error) {
        console.error('Failed to get token:', error);
        return null;
    }
}

/**
 * Clears the stored access token (logout).
 */
export async function clearToken() {
    try {
        await invoke('clear_access_token');
    } catch (error) {
        console.error('Failed to clear token:', error);
        throw error;
    }
}
