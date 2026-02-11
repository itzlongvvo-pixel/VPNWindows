/*
  Nera VPN™
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
*/
import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';

// --- 1. EXISTING STORES (Keep these for the Dashboard) ---
export const connected = writable(false);
export const server = writable('Tokyo, Japan');
export const killswitch = writable(true);
export const upload = writable('0 GB');
export const download = writable('0 GB');
export const ping = writable('-- ms');

// --- 2. NEW SECURITY VAULT (Fixes the Login Loop) ---
export const userState = writable({
    status: 'LOADING', // Options: 'LOADING' | 'AUTHENTICATED' | 'GUEST'
    publicKey: null,
    ip: null,
    error: null
});

// --- 3. THE GUARD FUNCTION (Syncs Rust -> Frontend) ---
export async function syncAuthState() {
    try {
        console.log("🔒 Security: Verifying Identity...");

        // Check for anonymous access token (new blind token auth)
        const token = await invoke("get_access_token");

        if (token && token.length > 0) {
            console.log("✅ Access Token Verified.");
            userState.set({
                status: 'AUTHENTICATED',
                publicKey: null, // Not used in blind token auth
                ip: "Connected",
                error: null
            });
        } else {
            console.log("⚠️ No Token. Guest Mode.");
            userState.set({
                status: 'GUEST',
                publicKey: null,
                ip: null,
                error: null
            });
        }
    } catch (e) {
        console.error("❌ Auth Failure", e);
        userState.set({
            status: 'GUEST',
            publicKey: null,
            ip: null,
            error: "Security Check Failed"
        });
    }
}