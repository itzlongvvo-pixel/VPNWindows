<!--
  Nera VPN™ - Custom Title Bar Component
  A completely frameless/invisible title bar with drag region and window controls.
-->
<script>
    import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

    let isMaximized = false;
    const appWindow = getCurrentWebviewWindow();

    // Check initial maximized state
    appWindow.isMaximized().then((maximized) => {
        isMaximized = maximized;
    });

    async function handleMinimize(event) {
        event.preventDefault();
        event.stopPropagation();
        console.log("Minimize clicked");
        try {
            await appWindow.minimize();
            console.log("Minimize success");
        } catch (e) {
            console.error("Minimize failed:", e);
        }
    }

    async function handleMaximize(event) {
        event.preventDefault();
        event.stopPropagation();
        console.log("Maximize clicked");
        try {
            await appWindow.toggleMaximize();
            isMaximized = await appWindow.isMaximized();
            console.log("Maximize success, isMaximized:", isMaximized);
        } catch (e) {
            console.error("Maximize failed:", e);
        }
    }

    async function handleClose(event) {
        event.preventDefault();
        event.stopPropagation();
        console.log("Close clicked");
        try {
            await appWindow.close();
            console.log("Close success");
        } catch (e) {
            console.error("Close failed:", e);
        }
    }
</script>

<div class="titlebar" data-tauri-drag-region>
    <div class="titlebar-brand">
        <img src="/nera-logo.svg" alt="Nera VPN" class="titlebar-logo" />
        <span class="titlebar-title">Nera VPN</span>
    </div>

    <div class="titlebar-controls">
        <button class="titlebar-button" on:click={handleMinimize} type="button">
            <svg viewBox="0 0 12 12" fill="currentColor">
                <rect x="2" y="5.5" width="8" height="1" />
            </svg>
        </button>

        <button class="titlebar-button" on:click={handleMaximize} type="button">
            {#if isMaximized}
                <svg
                    viewBox="0 0 12 12"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1"
                >
                    <rect x="3" y="3" width="6" height="6" />
                    <path d="M5 3V1.5H10.5V7H9" />
                </svg>
            {:else}
                <svg
                    viewBox="0 0 12 12"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1"
                >
                    <rect x="2" y="2" width="8" height="8" />
                </svg>
            {/if}
        </button>

        <button
            class="titlebar-button titlebar-close"
            on:click={handleClose}
            type="button"
        >
            <svg viewBox="0 0 12 12" fill="currentColor">
                <path
                    d="M2.5 2.5L9.5 9.5M9.5 2.5L2.5 9.5"
                    stroke="currentColor"
                    stroke-width="1.2"
                    stroke-linecap="round"
                />
            </svg>
        </button>
    </div>
</div>

<style>
    .titlebar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 32px;
        background: transparent;
        border: none;
        user-select: none;
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 9999;
    }

    .titlebar-brand {
        display: flex;
        align-items: center;
        gap: 8px;
        padding-left: 12px;
        pointer-events: none;
    }

    .titlebar-logo {
        width: 18px;
        height: 18px;
        object-fit: contain;
    }

    .titlebar-title {
        font-size: 12px;
        font-weight: 600;
        color: #94a3b8;
        letter-spacing: 0.5px;
    }

    .titlebar-controls {
        display: flex;
        height: 100%;
    }

    .titlebar-button {
        width: 46px;
        height: 100%;
        border: none;
        background: transparent;
        color: #94a3b8;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition:
            background-color 0.15s ease,
            color 0.15s ease;
        pointer-events: auto;
    }

    .titlebar-button svg {
        width: 12px;
        height: 12px;
        pointer-events: none;
    }

    .titlebar-button:hover {
        background: rgba(148, 163, 184, 0.15);
        color: #e2e8f0;
    }

    .titlebar-button:active {
        background: rgba(148, 163, 184, 0.25);
    }

    .titlebar-close:hover {
        background: #ef4444;
        color: white;
    }

    .titlebar-close:active {
        background: #dc2626;
    }
</style>
