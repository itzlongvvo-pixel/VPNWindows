<!--
  Nera VPN™ - Subscription Code Redemption
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  
  Anonymous token authentication UI component.
  Users enter their subscription code to receive an anonymous access token.
-->
<script>
  import { redeemSubscription } from "../lib/blindAuth.js";
  import { syncAuthState } from "../lib/stores.js";

  let subscriptionCode = "";
  let status = "idle"; // 'idle' | 'loading' | 'success' | 'error'
  let statusMessage = "";
  let errorMessage = "";

  // Simple formatting: just uppercase
  function formatCode(value) {
    // Determine if user is typing or pasting
    // We allow dashes if the user types them, but we don't force specific grouping
    // This supports both XXXX-XXXX-XXXX and DEV-ACTIVE-001 formats
    return value.toUpperCase();
  }

  function handleInput(event) {
    subscriptionCode = formatCode(event.target.value);
  }

  async function handleSubmit() {
    const cleaned = subscriptionCode.replace(/[^A-Z0-9]/g, "");
    if (cleaned.length < 8) {
      errorMessage = "Please enter a valid subscription code.";
      return;
    }

    status = "loading";
    errorMessage = "";

    try {
      await redeemSubscription(subscriptionCode, (msg) => {
        statusMessage = msg;
      });

      status = "success";
      statusMessage = "Authentication complete!";

      // Update the global auth state
      await syncAuthState();
    } catch (error) {
      status = "error";
      errorMessage = error.message || "Failed to redeem subscription code.";
    }
  }
</script>

<div class="redeem-container">
  <div class="redeem-card">
    <div class="card-header">
      <div class="logo">
        <svg viewBox="0 0 512 512" class="shield-icon">
          <defs>
            <linearGradient
              id="shieldGradient"
              x1="0%"
              y1="0%"
              x2="0%"
              y2="100%"
            >
              <stop offset="0%" stop-color="#4DF3FF" />
              <stop offset="50%" stop-color="#04D4FF" />
              <stop offset="100%" stop-color="#08FF9C" />
            </linearGradient>
            <linearGradient
              id="innerGradient"
              x1="0%"
              y1="0%"
              x2="0%"
              y2="100%"
            >
              <stop offset="0%" stop-color="#051729" />
              <stop offset="100%" stop-color="#021019" />
            </linearGradient>
            <linearGradient
              id="outlineGradient"
              x1="0%"
              y1="0%"
              x2="0%"
              y2="100%"
            >
              <stop offset="0%" stop-color="#7BFCFF" />
              <stop offset="100%" stop-color="#4DFFBA" />
            </linearGradient>
          </defs>
          <path
            d="M256 24
               80 86
               80 208
               80 240
               92 296
               120 352
               160 400
               212 438
               256 458
               300 438
               352 400
               392 352
               420 296
               432 240
               432 208
               432 86
               Z"
            fill="url(#shieldGradient)"
            stroke="url(#outlineGradient)"
            stroke-width="14"
            stroke-linejoin="round"
          />
          <path
            d="M256 72
               124 120
               124 208
               124 234
               134 280
               158 320
               190 352
               224 376
               256 390
               288 376
               322 352
               354 320
               378 280
               388 234
               388 208
               388 120
               Z"
            fill="url(#innerGradient)"
            stroke="#02141f"
            stroke-width="8"
            stroke-linejoin="round"
          />
          <path
            d="M256 112
               164 146
               164 210
               164 236
               174 264
               192 288
               212 306
               234 318
               256 326
               278 318
               300 306
               320 288
               338 264
               348 236
               348 210
               348 146
               Z"
            fill="none"
            stroke="#1AD2FF"
            stroke-width="10"
            stroke-linejoin="round"
          />
          <path
            d="M256 148
               188 172
               188 208
               188 226
               196 246
               210 262
               224 272
               240 280
               256 284
               272 280
               288 272
               302 262
               316 246
               324 226
               324 208
               324 172
               Z"
            fill="none"
            stroke="#3BF8BD"
            stroke-width="9"
            stroke-linejoin="round"
          />
          <path
            d="M256 192
               c-22 0 -40 18 -40 40
               c0 14 7 26 18 33
               l-10 54
               c-1 6 3 11 9 11h46
               c6 0 10 -5 9 -11l-10 -54
               c11 -7 18 -19 18 -33
               c0 -22 -18 -40 -40 -40z"
            fill="#0DF0B1"
            stroke="#061824"
            stroke-width="8"
            stroke-linejoin="round"
          />
          <path
            d="M200 140
               l56 -20
               56 20
               c4 1 6 5 5 9
               l-4 16
               c-1 4 -5 6 -9 5
               l-48 -14
               -48 14
               c-4 1 -8 -1 -9 -5
               l-4 -16
               c-1 -4 1 -8 5 -9z"
            fill="#16E4FF"
            stroke="#02141f"
            stroke-width="6"
            stroke-linejoin="round"
          />
        </svg>
      </div>
      <h1>Nera VPN</h1>
      <p class="subtitle">Enter your subscription code to activate</p>
    </div>

    <div class="card-body">
      {#if status === "success"}
        <div class="success-state">
          <div class="success-icon">✓</div>
          <p>Welcome to Nera VPN</p>
          <p class="success-sub">Your anonymous connection is ready.</p>
        </div>
      {:else}
        <div class="input-group">
          <label for="code-input">Subscription Code</label>
          <input
            id="code-input"
            type="text"
            value={subscriptionCode}
            on:input={handleInput}
            placeholder="XXXX-XXXX-XXXX"
            disabled={status === "loading"}
            maxlength="20"
            autocomplete="off"
            spellcheck="false"
          />
        </div>

        {#if errorMessage}
          <div class="error-message">{errorMessage}</div>
        {/if}

        {#if status === "loading"}
          <div class="status-indicator">
            <div class="spinner"></div>
            <span>{statusMessage}</span>
          </div>
        {/if}

        <button
          class="submit-btn"
          on:click={handleSubmit}
          disabled={status === "loading" || subscriptionCode.length < 8}
        >
          {#if status === "loading"}
            Processing...
          {:else}
            Activate VPN
          {/if}
        </button>
      {/if}
    </div>

    <div class="card-footer">
      <p>
        Don't have a code?
        <a href="https://neravpn.com/subscribe" target="_blank" rel="noopener">
          Get one here
        </a>
      </p>
    </div>
  </div>
</div>

<style>
  .redeem-container {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 2rem;
  }

  .redeem-card {
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(24px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 24px;
    width: 100%;
    max-width: 420px;
    overflow: hidden;
    box-shadow:
      0 25px 50px rgba(0, 0, 0, 0.5),
      0 0 100px rgba(34, 211, 238, 0.1);
  }

  .card-header {
    text-align: center;
    padding: 2.5rem 2rem 1.5rem;
    background: linear-gradient(
      180deg,
      rgba(34, 211, 238, 0.1) 0%,
      transparent 100%
    );
  }

  .logo {
    width: 80px;
    height: 80px;
    margin: 0 auto 1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    /* Background removed for new logo */
  }

  .shield-icon {
    width: 64px;
    height: 64px;
    /* Color removed as SVG has own colors */
  }

  h1 {
    font-size: 1.75rem;
    font-weight: 700;
    color: #fff;
    margin: 0 0 0.5rem;
    letter-spacing: -0.02em;
  }

  .subtitle {
    color: #94a3b8;
    font-size: 0.95rem;
    margin: 0;
  }

  .card-body {
    padding: 1.5rem 2rem 2rem;
  }

  .input-group {
    margin-bottom: 1.5rem;
  }

  label {
    display: block;
    color: #94a3b8;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
    font-weight: 500;
    text-align: center;
  }

  input {
    width: 100%;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 12px;
    color: #fff;
    font-size: 1.25rem;
    font-family: "SF Mono", "Fira Code", monospace;
    letter-spacing: 0.15em;
    text-align: center;
    outline: none;
    transition: all 0.2s ease;
    box-sizing: border-box;
  }

  input:focus {
    border-color: #22d3ee;
    box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.2);
  }

  input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  input::placeholder {
    color: #475569;
    letter-spacing: 0.15em;
  }

  .error-message {
    color: #ef4444;
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.2);
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-size: 0.9rem;
    margin-bottom: 1rem;
  }

  .status-indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    color: #22d3ee;
    font-size: 0.9rem;
    margin-bottom: 1rem;
  }

  .spinner {
    width: 18px;
    height: 18px;
    border: 2px solid rgba(34, 211, 238, 0.3);
    border-top-color: #22d3ee;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .submit-btn {
    width: 100%;
    padding: 1rem;
    border: none;
    border-radius: 12px;
    background: linear-gradient(135deg, #22d3ee 0%, #0ea5e9 100%);
    color: #0f172a;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: 0 4px 16px rgba(34, 211, 238, 0.3);
  }

  .submit-btn:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(34, 211, 238, 0.4);
  }

  .submit-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }

  .success-state {
    text-align: center;
    padding: 1rem 0;
  }

  .success-icon {
    width: 64px;
    height: 64px;
    background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 1rem;
    font-size: 2rem;
    color: #fff;
    box-shadow: 0 8px 32px rgba(34, 197, 94, 0.4);
  }

  .success-state p {
    color: #fff;
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0 0 0.25rem;
  }

  .success-sub {
    color: #94a3b8 !important;
    font-size: 0.95rem !important;
    font-weight: 400 !important;
  }

  .card-footer {
    padding: 1rem 2rem 1.5rem;
    text-align: center;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
  }

  .card-footer p {
    color: #64748b;
    font-size: 0.85rem;
    margin: 0;
  }

  .card-footer a {
    color: #22d3ee;
    text-decoration: none;
    font-weight: 500;
  }

  .card-footer a:hover {
    text-decoration: underline;
  }
</style>
