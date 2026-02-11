<script>
    import { registerUser, loginUser } from "../api.js";
    import { invoke } from "@tauri-apps/api/core";
    import { syncAuthState } from "../lib/stores.js";

    export let publicKey = "";
    export let onSignupSuccess;

    let mode = "login"; // 'register' or 'login'
    let email = "";
    let password = "";
    let confirmPassword = "";
    let rememberMe = true;

    let isLoading = false;
    let errorMessage = "";
    let successMessage = "";

    async function handleSubmit() {
        errorMessage = "";
        successMessage = "";

        if (!email || !password) {
            errorMessage = "Please fill in all fields.";
            return;
        }

        if (mode === "register" && password !== confirmPassword) {
            errorMessage = "Passwords do not match.";
            return;
        }

        isLoading = true;
        try {
            let result;
            if (mode === "login") {
                result = await loginUser(email, password, publicKey);
                successMessage = `Welcome back! IP: ${result.ip}`;
            } else {
                result = await registerUser(email, password, publicKey);
                successMessage = `Account created! IP: ${result.ip}`;
            }

            // --- UPDATE: Pass 'rememberMe' to backend ---
            // This ensures the backend knows whether to save keys to disk or not.
            await invoke("complete_registration", {
                ip: result.ip,
                remember: rememberMe,
            });

            // --- THE CRITICAL FIX ---
            // We tell the Security Vault to re-verify the user.
            await syncAuthState();
            // ------------------------
        } catch (err) {
            let msg = err.message || "Operation failed";
            if (msg.includes("UNIQUE constraint")) {
                errorMessage = "Account exists. Try logging in.";
            } else {
                errorMessage = msg;
            }
        } finally {
            isLoading = false;
        }
    }
</script>

<div class="auth-container">
    <div class="tabs">
        <button
            class:active={mode === "login"}
            on:click={() => (mode = "login")}>Sign In</button
        >
        <button
            class:active={mode === "register"}
            on:click={() => (mode = "register")}>Create Account</button
        >
    </div>

    <div class="form-content">
        {#if errorMessage}
            <div class="error">{errorMessage}</div>
        {/if}
        {#if successMessage}
            <div class="success">{successMessage}</div>
        {/if}

        {#if !successMessage}
            <div class="input-group">
                <input type="email" bind:value={email} placeholder="Email" />
            </div>
            <div class="input-group">
                <input
                    type="password"
                    bind:value={password}
                    placeholder="Password"
                />
            </div>
            {#if mode === "register"}
                <div class="input-group">
                    <input
                        type="password"
                        bind:value={confirmPassword}
                        placeholder="Confirm Password"
                    />
                </div>
            {/if}

            {#if mode === "login"}
                <div class="options-row">
                    <label class="remember-me">
                        <input type="checkbox" bind:checked={rememberMe} />
                        <span>Remember me</span>
                    </label>
                    <a href="#" class="forgot-pass">Forgot Password?</a>
                </div>
            {/if}

            <button
                class="submit-btn"
                on:click={handleSubmit}
                disabled={isLoading}
            >
                {#if isLoading}
                    <div class="spinner-sm"></div>
                    Processing...
                {:else}
                    {mode === "register" ? "Sign Up" : "Sign In"}
                {/if}
            </button>
        {/if}
    </div>
</div>

<style>
    .auth-container {
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        width: 100%;
        max-width: 380px;
        margin: 0 auto;
        overflow: hidden;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }
    .tabs {
        display: flex;
        background: rgba(0, 0, 0, 0.2);
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .tabs button {
        flex: 1;
        padding: 1rem;
        background: transparent;
        border: none;
        color: #94a3b8;
        cursor: pointer;
        font-weight: 600;
        transition: all 0.2s;
        border-bottom: 2px solid transparent;
    }
    .tabs button.active {
        color: #fff;
        border-bottom-color: #22d3ee;
        background: rgba(255, 255, 255, 0.02);
    }
    .form-content {
        padding: 2rem;
    }
    .input-group {
        margin-bottom: 1rem;
    }
    input {
        width: 100%;
        padding: 0.8rem 0;
        background: transparent;
        border: none;
        border-bottom: 1px solid #334155;
        color: white;
        font-size: 1rem;
        outline: none;
        transition: border-color 0.3s;
    }
    input:focus {
        border-bottom-color: #22d3ee;
    }
    .options-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.8rem;
        color: #94a3b8;
        margin-bottom: 1.5rem;
    }
    .remember-me {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        cursor: pointer;
    }
    .forgot-pass {
        color: #22d3ee;
        text-decoration: none;
    }
    .submit-btn {
        width: 100%;
        padding: 0.8rem;
        border: none;
        border-radius: 8px;
        background: linear-gradient(135deg, #22d3ee 0%, #0ea5e9 100%);
        color: #0f172a;
        font-weight: 700;
        cursor: pointer;
    }
    .submit-btn:disabled {
        opacity: 0.7;
        cursor: not-allowed;
    }
    .error {
        color: #ef4444;
        background: rgba(239, 68, 68, 0.1);
        padding: 0.8rem;
        border-radius: 6px;
        margin-bottom: 1rem;
    }
    .success {
        color: #22c55e;
        background: rgba(34, 197, 94, 0.1);
        padding: 0.8rem;
        border-radius: 6px;
        margin-bottom: 1rem;
        text-align: center;
    }
    .spinner-sm {
        display: inline-block;
        width: 12px;
        height: 12px;
        border: 2px solid rgba(0, 0, 0, 0.3);
        border-top-color: #000;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-right: 5px;
    }
    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }
</style>
