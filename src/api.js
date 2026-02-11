import { invoke } from '@tauri-apps/api/core';

// We now ask Rust to handle the network call to bypass CORS/Mixed Content blocks
export async function registerUser(email, password, publicKey) {
  try {
    console.log("Sending registration via Rust Proxy...");

    // Call the new Rust command 'register_account'
    // FIX: Rust expects 'publicKey' (matching the error message), not 'public_key'
    const responseText = await invoke('register_account', {
      email: email,
      password: password,
      publicKey: publicKey, // <--- CHANGED FROM public_key TO publicKey
    });

    // Rust returns the raw JSON string from the server, so we parse it here
    const data = JSON.parse(responseText);

    if (data.error) {
      throw new Error(data.error);
    }

    return data; // Returns { success: true, ip: "10.66.66.xx" }
  } catch (error) {
    console.error('Registration Error:', error);
    throw error; // Passes the error up to the UI to show the red box
  }
}

// Add this new function
export async function loginUser(email, password, publicKey) {
  try {
    console.log("Logging in via Rust Proxy...");
    const responseText = await invoke('login_account', {
      email: email,
      password: password,
      publicKey: publicKey, // CamelCase for JS, snake_case for Rust
    });
    const data = JSON.parse(responseText);
    if (data.error) throw new Error(data.error);
    return data;
  } catch (error) {
    console.error('Login Error:', error);
    throw error;
  }
}