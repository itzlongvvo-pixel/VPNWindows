<!--
  Nera VPN™
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  Nera VPN™ is a trademark of Vio Holdings LLC.
  This software is proprietary and confidential. Unauthorized copying,
  distribution, modification, or use of this software, via any medium,
  is strictly prohibited without written permission from the copyright holder.
  The source code and binaries are protected by copyright law and international treaties.
-->
<script>
  import { onMount } from "svelte";
  import { getVersion } from "@tauri-apps/api/app";
  import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { invoke } from "@tauri-apps/api/core"; // Ensure invoke is imported
  import { listen } from "@tauri-apps/api/event";
  import Protection from "./components/Protection.svelte"; // Ensure correct path
  import RedeemToken from "./components/RedeemToken.svelte";
  import { userState, syncAuthState } from "./lib/stores.js"; // Import the Truth Vault
  import Globe from "./lib/Globe.svelte"; // Import Globe component
  import TitleBar from "./components/TitleBar.svelte"; // Custom frameless window title bar
  import { getPublicIPAndLocation } from "./lib/ipLocation";
  const appWindow = getCurrentWebviewWindow();

  const SETTINGS_KEY = "nera-vpn-settings";

  // Fake routes for now; all still use nera.conf
  const ROUTES = [
    { key: "tokyo", label: "Tokyo, Japan", lat: 35.6, lng: 139.6 },
    { key: "la", label: "Los Angeles, USA", lat: 34.05, lng: -118.24 },
    { key: "singapore", label: "Singapore", lat: 1.35, lng: 103.82 },
    { key: "london", label: "London, UK", lat: 51.5, lng: -0.12 },
  ];

  // --- Protection State Bindings ---
  let protection; // Component instance

  let connected = false;
  // vpnStatus: 'inactive' | 'connecting' | 'connected'
  let vpnStatus = "inactive";

  // Sync vpnStatus with connected state
  $: if (connected) {
    vpnStatus = "connected";
  } else if (vpnStatus !== "connecting") {
    vpnStatus = "inactive";
  }

  let killswitch = false;
  let recovery = false;
  let vpnError = "";

  // UI Local State
  let isBusy = false; // Just for UI button loader
  // actually Protection doesn't expose busy state yet, but prompt said "App UI... Does not guess".
  // We'll keep local isBusy for button feedback while awaiting the async method.

  // Route state (persisted in backend now)
  // null = "Smart Connect" mode (random server)
  let selectedRouteKey = null;
  let wasSmartConnectMode = true; // Track if user was in Smart Connect mode before connecting
  let routeMenuOpen = false;

  // Session controls (persisted in local storage, except killswitch/server)
  let launchOnStartup = true;
  let autoConnectWifi = true;
  let showLocation = true; // New state

  let startMinimized = false;
  let currentTheme = "dark";

  // Advanced Features State
  let neraVaultEnabled = false;
  let shieldZeroStats = {
    enabled: false,
    session_scanned: 0,
    session_blocked: 0,
    total_scanned: 0,
    total_blocked: 0,
    whitelist_count: 0,
  };
  let shieldZeroThreatLog = [];
  let shieldZeroWhitelist = [];
  let shieldZeroPollingInterval = null;
  let shieldZeroExpanded = false; // Panel expand/collapse
  let splitTunnelingEnabled = false;
  let splitTunnelingApps = []; // List of app paths for split tunneling
  let portForwardingEnabled = false;
  let forwardedPort = null; // Assigned port when enabled

  let stealthModeEnabled = false; // DPI Stealth Mode toggle
  // Load persisted stealth setting at init
  (async () => {
    try {
      const settings = await invoke("get_settings");
      if (settings && settings.dpi_stealth_enabled) {
        stealthModeEnabled = true;
        console.log("[Stealth] Loaded persisted setting: enabled");
      }
    } catch (e) {
      console.warn("[Stealth] Could not load persisted setting:", e);
    }
  })();

  // Client Public Key (for Session Controls display)
  let clientPublicKey = "";

  $: document.body.className =
    currentTheme === "light" ? "" : `theme-${currentTheme}`;

  let appVersion = "";
  let importMessage = "";

  // "Check my IP" state
  let ipChecking = false;
  let ipData = null;
  let ipError = "";
  let lastKnownIp = ""; // For burst polling comparison
  let preVpnIp = ""; // Store the real IP before VPN connects (for split tunnel display)
  let pollingInterval; // To manage burst timer

  // Registration State
  let showRegistrationModal = false;
  let regStep = 0; // 0: Idle, 1: Generating/Registering, 2: Success, 3: Error
  let regError = "";
  let regSuccessMsg = "";

  // Regenerate Key (Identity Reset) Modal
  let showRegenModal = false;

  // let userPublicKey = ""; // REMOVED: Managed by Store
  // let loadingAuth = true; // REMOVED: Managed by Store

  // About Modal State
  let showAboutModal = false;

  // Traffic Bar Graph Data
  // Traffic Bar Graph Data
  let trafficValues = new Array(20).fill(5); // 20 bars
  let unlistenTraffic;
  let downloadSpeed = "0 B/s";
  let uploadSpeed = "0 B/s";
  let pingValue = "—";
  let peakSpeed = "0 B/s";
  let currentMaxScale = 1024 * 1024; // Start at 1MB/s
  let scaleLabel = "1.0 MB/s";

  $: if (connected) {
    startTraffic();
    // Wait for the tunnel to stabilize before checking IP (0.5s delay)
    setTimeout(() => checkIp(false, true), 500);

    // Activate WFP split tunnel if enabled — delay to allow tunnel to stabilize
    if (splitTunnelingEnabled) {
      setTimeout(() => {
        invoke("wfp_activate")
          .then(() => {
            console.log("[SplitTunnel] Activated on VPN connect");
          })
          .catch((e) => {
            console.error("[SplitTunnel] Failed to activate:", e);
          });
      }, 3000); // Wait 3s for WG tunnel to fully establish
    }
  } else {
    stopTraffic();
    // Check immediately on disconnect to show real IP
    checkIp(false, true);
    // Deactivate WFP split tunnel on disconnect
    invoke("wfp_deactivate").catch((e) => {
      console.warn("WFP deactivate on disconnect:", e);
    });
  }

  async function startTraffic() {
    stopTraffic();

    // Start backend traffic monitoring
    try {
      await invoke("start_traffic_monitoring");
      console.log("Traffic monitoring started");
    } catch (e) {
      console.error("Failed to start traffic monitoring:", e);
    }

    unlistenTraffic = await listen("traffic-update", (event) => {
      const { download, upload, ping } = event.payload;

      // Update Text
      downloadSpeed = formatSpeed(download);
      uploadSpeed = formatSpeed(upload);
      if (ping) pingValue = ping;

      // Update Graph (Dynamic Scaling)
      // 1. Zoom Out (Instant)
      if (download > currentMaxScale) {
        currentMaxScale = download;
      } else {
        // 2. Zoom In (Decay 5% per tick, floor at 1MB)
        let newScale = currentMaxScale * 0.95;
        if (newScale < 1024 * 1024) newScale = 1024 * 1024;
        currentMaxScale = newScale;
      }
      scaleLabel = formatSpeed(currentMaxScale);

      let pct = (download / currentMaxScale) * 100;

      if (pct > 100) pct = 100;
      if (pct < 2) pct = 2; // Tiny floor so line exists

      trafficValues = [
        pct,
        ...trafficValues.slice(0, trafficValues.length - 1),
      ];

      // Calculate Peak for UI
      // Crude approximation since we only store %, but we can track max bytes seen
      if (download > maxDownloadBytes) {
        maxDownloadBytes = download;
        peakSpeed = formatSpeed(maxDownloadBytes);
      }
    });
  }

  let maxDownloadBytes = 0;

  function stopTraffic() {
    if (unlistenTraffic) {
      unlistenTraffic();
      unlistenTraffic = null;
    }

    // Stop backend traffic monitoring
    invoke("stop_traffic_monitoring").catch((e) => {
      console.warn("Failed to stop traffic monitoring:", e);
    });

    trafficValues = new Array(20).fill(5);
    downloadSpeed = "0 B/s";
    uploadSpeed = "0 B/s";
    pingValue = "—";
  }

  function formatSpeed(bytes) {
    if (bytes < 1024) return bytes + " B/s";
    const k = bytes / 1024;
    if (k < 1024) return k.toFixed(1) + " KB/s";
    const m = k / 1024;
    return m.toFixed(1) + " MB/s";
  }

  // Generate a smooth SVG path from trafficValues
  $: trafficPath = (function () {
    if (!trafficValues || trafficValues.length === 0) return "";

    const max = 100; // max height %
    const count = trafficValues.length;
    const step = 100 / (count - 1);

    // Helper to map value to Y coordinate (inverted because SVG Y grows down)
    const getY = (pc) => 100 - pc;

    // Start point
    let d = `M 0,${getY(trafficValues[0])}`;

    // Simple smooth curve: usage of quadratic bezier or just line to for simplicity?
    // The screenshot shows nice waves. Let's use a simplified Catmull-Rom-like smoothing
    // or just cubic bezier control points based on neighbors.
    // For brevity/robustness in a single file, we'll do simple quadratic curves between midpoints.

    for (let i = 0; i < count - 1; i++) {
      const x0 = i * step;
      const y0 = getY(trafficValues[i]);
      const x1 = (i + 1) * step;
      const y1 = getY(trafficValues[i + 1]);

      // Midpoint
      const mx = (x0 + x1) / 2;
      const my = (y0 + y1) / 2;

      // Control point for quadratic could be just the start point? No that's sharp.
      // Let's us cubic bezier: (x0 + step/2, y0) -> (x1 - step/2, y1)
      const cp1x = x0 + step / 3;
      const cp1y = y0;
      const cp2x = x1 - step / 3;
      const cp2y = y1;

      d += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${x1},${y1}`;
    }

    return d;
  })();

  function currentRouteLabel() {
    const found = ROUTES.find((r) => r.key === selectedRouteKey);
    return found ? found.label : ROUTES[0].label;
  }

  function loadSettings() {
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (!raw) return;
      const data = JSON.parse(raw);

      if (typeof data.launchOnStartup === "boolean")
        launchOnStartup = data.launchOnStartup;
      if (typeof data.autoConnectWifi === "boolean")
        autoConnectWifi = data.autoConnectWifi;
      if (typeof data.showLocation === "boolean")
        showLocation = data.showLocation;
      if (typeof data.startMinimized === "boolean")
        startMinimized = data.startMinimized;
      if (data.theme) {
        // Migration: map "default" to "light", "space"/"nebula" to "dark" maybe?
        if (data.theme === "default") currentTheme = "light";
        else if (data.theme === "nebula")
          currentTheme = "space"; // map old nebula to space
        else currentTheme = data.theme;
      } else {
        currentTheme = "dark";
      }

      // Note: selectedRouteKey is now managed by backend (get_selected_server)

      // We do NOT load 'killswitch' from local prefs anymore, backend is source of truth.
    } catch (e) {
      console.error("Failed to load settings", e);
    }
  }

  function saveSettings() {
    try {
      const data = {
        // killswitch: ref removed
        // selectedRouteKey: ref removed (backend)
        launchOnStartup,
        autoConnectWifi,
        showLocation,

        startMinimized,
        theme: currentTheme,
      };
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(data));
    } catch (e) {
      console.error("Failed to save settings", e);
    }
  }

  async function selectRoute(key) {
    // Clicking already-selected route returns to Smart Connect mode (unless already in Smart Connect)
    if (selectedRouteKey === key && key !== null) {
      selectedRouteKey = null;
      wasSmartConnectMode = true; // User explicitly chose Smart Connect
      try {
        await invoke("set_selected_server", { serverKey: "" });
      } catch (e) {
        console.error("Failed to clear server selection", e);
      }
      return;
    }

    // If clicking Smart Connect (null) and already in Smart Connect, do nothing
    if (key === null && selectedRouteKey === null) {
      return;
    }

    selectedRouteKey = key;
    wasSmartConnectMode = key === null; // Track if user chose Smart Connect or a specific server
    routeMenuOpen = false;
    // Persist to backend
    try {
      await invoke("set_selected_server", { serverKey: key || "" });
    } catch (e) {
      console.error("Failed to set server", e);
    }
  }

  async function toggle() {
    if (isBusy) return;
    isBusy = true;
    importMessage = "";

    try {
      if (connected) {
        await protection.disconnect();

        // Restore to Smart Connect mode if that was the original selection
        if (wasSmartConnectMode) {
          selectedRouteKey = null;
          console.log("Disconnect: Restoring to Smart Connect mode");
        }
        // If user manually selected a server, keep it selected
      } else {
        // CONNECTING
        vpnStatus = "connecting";

        // Capture current IP before connecting
        lastKnownIp = ipData ? ipData.ip : "";
        preVpnIp = lastKnownIp; // Store for split tunnel HUD display

        // Remember if we're in Smart Connect mode before picking a server
        wasSmartConnectMode = selectedRouteKey === null;

        // Smart Connect: Pick a random server if none selected
        let serverToConnect = selectedRouteKey;
        if (!serverToConnect) {
          const randomIndex = Math.floor(Math.random() * ROUTES.length);
          serverToConnect = ROUTES[randomIndex].key;
          selectedRouteKey = serverToConnect; // Update UI to show selected server
          console.log("Smart Connect: Selected", serverToConnect);
        }

        // Pass the selected key to connect
        await protection.connect(serverToConnect);

        // Trigger burst polling explicitly
        waitForNewIp();
      }
    } catch (e) {
      console.error("Toggle failed", e);
      vpnStatus = "inactive"; // Reset status on failure
    } finally {
      isBusy = false;
    }
  }

  // Change Server: Disconnect, pick different random server, reconnect
  async function changeServer() {
    if (isBusy || !connected) return;
    isBusy = true;

    try {
      // 1. Disconnect
      await protection.disconnect();

      // 2. Pick a different random server
      const currentServer = selectedRouteKey;
      const availableServers = ROUTES.filter((r) => r.key !== currentServer);
      const randomIndex = Math.floor(Math.random() * availableServers.length);
      const newServer = availableServers[randomIndex].key;
      selectedRouteKey = newServer;
      console.log(
        "Change Server: Switching from",
        currentServer,
        "to",
        newServer,
      );

      // 3. Small delay for tunnel cleanup
      await new Promise((resolve) => setTimeout(resolve, 500));

      // 4. Reconnect to new server
      lastKnownIp = ipData ? ipData.ip : "";
      await protection.connect(newServer);
      waitForNewIp();
    } catch (e) {
      console.error("Change server failed:", e);
      vpnError = String(e);
    } finally {
      isBusy = false;
    }
  }

  async function handleLogout() {
    try {
      // Disconnect VPN first if connected
      if (connected) {
        console.log("Disconnecting VPN before sign out...");
        await protection.disconnect();
      }

      await invoke("logout");
      await syncAuthState(); // Update the Vault

      // Reset server selection to Smart Connect mode
      selectedRouteKey = null;
      wasSmartConnectMode = true;

      showRegistrationModal = false; // Reset any modals
      console.log("Logged out successfully");
    } catch (e) {
      console.error("Logout failed", e);
    }
  }

  async function handleImportConfig() {
    // Import logic currently depends on invoke.
    // Protection component handles "protection". Config import is borderline.
  }

  // --- Advanced Features Handlers ---
  async function toggleNeraVault() {
    try {
      await invoke("toggle_netshield", { enabled: neraVaultEnabled });
      console.log("Shield Zero:", neraVaultEnabled ? "enabled" : "disabled");

      if (neraVaultEnabled) {
        // Start polling stats every 2 seconds
        await refreshShieldZeroStats();
        shieldZeroPollingInterval = setInterval(refreshShieldZeroStats, 2000);
      } else {
        // Stop polling
        if (shieldZeroPollingInterval) {
          clearInterval(shieldZeroPollingInterval);
          shieldZeroPollingInterval = null;
        }
        shieldZeroStats = {
          enabled: false,
          session_scanned: 0,
          session_blocked: 0,
          total_scanned: 0,
          total_blocked: 0,
          whitelist_count: 0,
        };
        shieldZeroThreatLog = [];
      }
    } catch (e) {
      console.error("Failed to toggle Shield Zero:", e);
      neraVaultEnabled = !neraVaultEnabled; // Revert on error
    }
  }

  async function refreshShieldZeroStats() {
    try {
      shieldZeroStats = await invoke("shield_zero_stats");
      shieldZeroThreatLog = await invoke("get_threat_log");
      shieldZeroWhitelist = await invoke("get_whitelist");
    } catch (e) {
      console.warn("Shield Zero stats refresh failed:", e);
    }
  }

  async function whitelistDomain(domain) {
    try {
      await invoke("whitelist_domain", { domain });
      await refreshShieldZeroStats();
      console.log("[Shield Zero] Whitelisted:", domain);
    } catch (e) {
      console.error("Failed to whitelist domain:", e);
    }
  }

  async function removeWhitelist(domain) {
    try {
      await invoke("remove_whitelist", { domain });
      await refreshShieldZeroStats();
      console.log("[Shield Zero] Removed from whitelist:", domain);
    } catch (e) {
      console.error("Failed to remove from whitelist:", e);
    }
  }

  async function toggleSplitTunneling() {
    try {
      // Set mode based on enabled state
      const mode = splitTunnelingEnabled ? "bypass" : "disabled";
      await invoke("wfp_set_mode", { mode });

      // Activate/deactivate based on VPN status
      if (splitTunnelingEnabled && connected) {
        await invoke("wfp_activate");
      } else if (!splitTunnelingEnabled) {
        await invoke("wfp_deactivate");
      }

      console.log(
        "Split Tunneling (WFP):",
        splitTunnelingEnabled ? "enabled" : "disabled",
      );
    } catch (e) {
      console.error("Failed to toggle Split Tunneling:", e);
      splitTunnelingEnabled = !splitTunnelingEnabled; // Revert on error
    }
  }

  async function addSplitTunnelApp() {
    try {
      // Open file picker for executable
      const selected = await invoke("pick_executable");
      if (selected && !splitTunnelingApps.includes(selected)) {
        // Extract app name from path
        const appName = selected.split("\\").pop().replace(".exe", "");

        // Add to WFP backend
        await invoke("wfp_add_app", {
          name: appName,
          exePath: selected,
        });

        splitTunnelingApps = [...splitTunnelingApps, selected];
      }
    } catch (e) {
      console.error("Failed to add split tunnel app:", e);
    }
  }

  async function removeSplitTunnelApp(app) {
    try {
      // Remove from WFP backend
      await invoke("wfp_remove_app", { exePath: app });
      splitTunnelingApps = splitTunnelingApps.filter((a) => a !== app);
    } catch (e) {
      console.error("Failed to remove split tunnel app:", e);
    }
  }

  let portToggling = false;
  async function togglePortForwarding() {
    if (portToggling) {
      // Rapid click — revert the checkbox and bail
      portForwardingEnabled = !portForwardingEnabled;
      return;
    }
    portToggling = true;
    try {
      const result = await invoke("toggle_port_forwarding", {
        enabled: portForwardingEnabled,
      });
      if (portForwardingEnabled && result) {
        forwardedPort = result; // Backend returns the assigned port
      } else {
        forwardedPort = null;
      }
      console.log(
        "Port Forwarding:",
        portForwardingEnabled ? `enabled on port ${forwardedPort}` : "disabled",
      );
    } catch (e) {
      console.error("Failed to toggle Port Forwarding:", e);
      portForwardingEnabled = !portForwardingEnabled; // Revert on error
    } finally {
      portToggling = false;
    }
  }

  let portRefreshing = false;
  async function refreshPort() {
    if (portRefreshing || !portForwardingEnabled) return;
    portRefreshing = true;
    try {
      // Release current port
      await invoke("toggle_port_forwarding", { enabled: false });
      // Request a new one
      const result = await invoke("toggle_port_forwarding", { enabled: true });
      if (result) {
        forwardedPort = result;
        console.log("Port Forwarding: refreshed to port", forwardedPort);
      }
    } catch (e) {
      console.error("Failed to refresh port:", e);
    } finally {
      portRefreshing = false;
    }
  }

  let portCopied = false;
  async function copyPort() {
    if (!forwardedPort) return;
    try {
      await navigator.clipboard.writeText(String(forwardedPort));
      portCopied = true;
      setTimeout(() => (portCopied = false), 1500);
    } catch (e) {
      console.error("Failed to copy port:", e);
    }
  }

  async function toggleStealth() {
    // bind:checked already flipped stealthModeEnabled — just tell the backend
    try {
      await invoke("toggle_dpi_stealth", { enabled: stealthModeEnabled });
      console.log(
        `[Stealth] Mode ${stealthModeEnabled ? "enabled" : "disabled"}`,
      );
    } catch (e) {
      console.error("[Stealth] Toggle failed:", e);
      stealthModeEnabled = !stealthModeEnabled; // Revert on error
    }
  }

  // Re-adding invoke for config import

  async function doImport() {
    // renamed to avoid conflict/confusion
    importMessage = "";
    try {
      const destPath = await invoke("import_wireguard_config");
      console.log("Config saved to:", destPath);
      importMessage = "Config imported successfully.";
    } catch (error) {
      console.error("Import config failed:", error);
      if (String(error).includes("No file selected")) {
        importMessage = "";
      } else {
        importMessage = "Failed to import config.";
      }
    }
  }

  // --- Registration Logic ---
  async function checkUserKey() {
    try {
      const key = await invoke("get_user_status");
      if (!key) {
        // No key found, remain in Guest state
        // startRegistration(); // <-- REMOVED auto-trigger
      } else {
        console.log("User key found:", key);
        userPublicKey = key;
      }
    } catch (e) {
      console.error("Failed to check user status", e);
    } finally {
      loadingAuth = false;
    }
  }

  function startRegistration() {
    // Show confirmation modal instead of silently resetting
    showRegenModal = true;
  }

  async function confirmRegenKey() {
    showRegenModal = false;
    isBusy = true;

    try {
      // 1. Disconnect VPN if active
      if (connected) {
        console.log("[RegenKey] Disconnecting VPN before identity reset...");
        await protection.disconnect();
      }

      // 2. Clear all keys and tokens (same as logout)
      await invoke("logout");
      console.log("[RegenKey] Identity wiped. Old keys destroyed.");

      // 3. Reset UI state
      selectedRouteKey = null;
      wasSmartConnectMode = true;
      clientPublicKey = "";

      // 4. Drop to Guest mode → shows RedeemToken screen
      await syncAuthState();
      console.log(
        "[RegenKey] Ready for new identity. Awaiting subscription code.",
      );
    } catch (e) {
      console.error("[RegenKey] Failed:", e);
      vpnError = "Identity reset failed: " + String(e);
    } finally {
      isBusy = false;
    }
  }

  function closeRegModal() {
    if (regStep === 2) {
      showRegistrationModal = false;
      regStep = 0;
    }
    // If error (3), user might want to close or retry.
    if (regStep === 3) {
      showRegistrationModal = false;
    }
  }

  // Robust IP + Location lookup
  // Robust IP + Location lookup
  // Robust IP + Location lookup
  async function checkIp(silent = false, force = false) {
    if (!silent) ipChecking = true;

    try {
      const data = await getPublicIPAndLocation(force);
      if (!data) throw new Error("Failed to detect IP");

      ipData = data;
      ipError = "";
      return data.ip;
    } catch (e) {
      console.error("IP check failed", e);
      if (!ipData) ipError = "OFFLINE";
      return null;
    } finally {
      if (!silent) ipChecking = false;
    }
  }

  async function waitForNewIp() {
    console.log("Starting smart burst polling...");
    const startTime = performance.now();
    let attempts = 0;
    const maxAttempts = 20; // 20 * 500ms = 10s max

    if (pollingInterval) clearInterval(pollingInterval);

    // Initial check (force bypass cache)
    const current = await checkIp(true, true);
    if (current && current !== lastKnownIp) {
      const duration = ((performance.now() - startTime) / 1000).toFixed(2);
      console.log(`Secured in ${duration}s`, current);
      return;
    }

    pollingInterval = setInterval(async () => {
      attempts++;
      if (attempts >= maxAttempts) {
        console.log("Burst polling timed out (limit reached).");
        clearInterval(pollingInterval);
        return;
      }

      const ip = await checkIp(true, true);
      if (ip && ip !== lastKnownIp) {
        const duration = ((performance.now() - startTime) / 1000).toFixed(2);
        console.log(`Secured in ${duration}s`, ip);
        clearInterval(pollingInterval);
      }
    }, 500);
  }

  onMount(async () => {
    // 1. Check for Access Token (Anonymous Blind Token Auth)
    await syncAuthState();

    // await checkUserKey(); // REPLACED - no longer using email/password auth

    loadSettings();

    // Load split tunnel config from backend (persisted in split_tunnel_v2.json)
    try {
      const stConfig = await invoke("wfp_get_config");
      if (stConfig && stConfig.mode && stConfig.mode !== "disabled") {
        splitTunnelingEnabled = true;
        console.log(
          "[SplitTunnel] Loaded persisted config: mode=",
          stConfig.mode,
          "apps=",
          stConfig.rules?.length || 0,
        );
      }
      // Load persisted app list
      if (stConfig && stConfig.rules) {
        splitTunnelingApps = stConfig.rules
          .filter((r) => r.type === "App")
          .map((r) => r.value?.exe_path || "");
      }
    } catch (e) {
      console.warn("[SplitTunnel] Could not load config:", e);
    }

    if (startMinimized) {
      try {
        console.log("Start Minimized is TRUE. Hiding window now.");
        await appWindow.hide();
      } catch (e) {
        console.error("Failed to hide on launch", e);
      }
    }

    try {
      appVersion = await getVersion();
    } catch (e) {
      console.error("Failed to get app version", e);
    }

    try {
      const saved = await invoke("get_selected_server");
      // Backend returns "" for Smart Connect, but UI uses null
      selectedRouteKey = saved || null;
      wasSmartConnectMode = selectedRouteKey === null;
      console.log(
        "Loaded selection:",
        selectedRouteKey,
        "SmartMode:",
        wasSmartConnectMode,
      );
    } catch (e) {
      console.error("Failed to get selected server", e);
    }

    // Initial check
    checkIp();

    // Fetch client public key for display
    try {
      clientPublicKey = await invoke("get_client_public_key");
    } catch (e) {
      console.warn("Failed to get client public key:", e);
    }

    // Poll every 2 seconds to catch ANY network change (VPN or otherwise)
    const ipInterval = setInterval(checkIp, 2000);

    return () => {
      clearInterval(ipInterval);
      stopTraffic();
    };
  });
</script>

<main>
  <TitleBar />
  <div class="background">
    <Globe
      focusLocation={connected
        ? ROUTES.find((r) => r.key === selectedRouteKey)
        : null}
    />
    <div class="glow glow-top"></div>
    <div class="glow glow-bottom"></div>
  </div>

  {#if $userState.status === "LOADING"}
    <!-- State 1: Loading -->
    <div class="auth-loading">
      <div class="spinner"></div>
      <p>Verifying Identity...</p>
    </div>
  {:else if $userState.status === "AUTHENTICATED"}
    <!-- State 2: Authenticated (Show Dashboard) -->
    <!-- HUD Layout -->

    <!-- Top Left: IP & Location -->
    <div class="hud-panel top-left">
      <!-- Connection Status HUD -->
      <div class="status-hud">
        {#if vpnStatus === "inactive"}
          <div class="status-dot red"></div>
          <span class="status-text">Inactive</span>
        {:else if vpnStatus === "connecting"}
          <div class="status-dot yellow animate-pulse"></div>
          <span class="status-text">Finding Server...</span>
        {:else if vpnStatus === "connected"}
          <div class="status-dot green"></div>
          <span class="status-text">Connected Securely</span>
          {#if stealthModeEnabled}
            <span class="stealth-badge">🛡️ STEALTH</span>
          {/if}
        {/if}
      </div>
    </div>
    <div class="hud-panel bottom-right">
      <div class="ip-display">
        <div class="ip-row">
          <span class="ip-label"
            >{connected && splitTunnelingEnabled
              ? "VPN TUNNEL"
              : "CURRENT IP"}</span
          >
          <span class="ip-value"
            >{ipData ? ipData.ip : ipChecking ? "Checking..." : "---"}</span
          >
        </div>
        {#if connected && splitTunnelingEnabled && preVpnIp}
          <div class="ip-row split-tunnel-row">
            <span class="ip-label split-label">SPLIT TUNNEL</span>
            <span class="ip-value split-value">{preVpnIp}</span>
          </div>
        {/if}
        {#if showLocation && ipData && ipData.country}
          <div class="ip-row location-row">
            <span class="location-icon">📍</span>
            <span class="location-value"
              >{ipData.city ? `${ipData.city}, ` : ""}{ipData.country}</span
            >
          </div>
        {/if}
        {#if ipError}
          <div class="ip-error">OFFLINE</div>
        {/if}
      </div>
    </div>

    <!-- Copyright Footer REMOVED (Moved to About) -->

    <!-- Top Right Routes: Location Selector -->
    <div class="hud-panel top-right-routes">
      <div class="panel-header">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          stroke-width="1.5"
          stroke="currentColor"
          class="header-icon"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.546-3.1 1.487-4.305"
          />
        </svg>
        <span class="header-title">Locations</span>
      </div>

      <!-- Collapsed Header is Icon Only via CSS -->

      <!-- Route Content -->
      <div class="route-content">
        <!-- Change Server Button (only visible when connected) -->
        {#if connected}
          <button
            class="change-server-btn"
            on:click={changeServer}
            disabled={isBusy}
          >
            🔄 Change Server
          </button>
        {/if}

        <div class="route-list">
          <!-- Smart Connect Option -->
          <button
            class="route-item smart-connect-item"
            on:click={() => selectRoute(null)}
          >
            <span
              class={`route-dot ${selectedRouteKey === null ? "active smart" : ""}`}
            ></span>
            <span class="route-label">Smart Connect</span>
            {#if selectedRouteKey === null}
              <span class="check">✓</span>
            {/if}
          </button>

          {#each ROUTES as route}
            <button class="route-item" on:click={() => selectRoute(route.key)}>
              <span
                class={`route-dot ${route.key === selectedRouteKey ? "active" : ""}`}
              ></span>
              <span class="route-label">{route.label}</span>
              {#if route.key === selectedRouteKey}
                <span class="check">✓</span>
              {/if}
            </button>
          {/each}
        </div>
      </div>
    </div>

    <!-- Top Right: Config & Controls -->
    <div class="hud-panel top-right">
      <div class="panel-header">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          stroke-width="1.5"
          stroke="currentColor"
          class="header-icon"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75"
          />
        </svg>
        <span class="header-title">Session Controls</span>
      </div>
      <div class="options-list">
        <!-- Auto-Connect -->
        <label class="control-row">
          <span>Auto-Connect</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={autoConnectWifi}
              on:change={saveSettings}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>

        <!-- Launch on Startup -->
        <label class="control-row">
          <span>Launch on Startup</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={launchOnStartup}
              on:change={saveSettings}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>

        <!-- Start Minimized -->
        <label class="control-row">
          <span>Start Minimized</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={startMinimized}
              on:change={saveSettings}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>

        <!-- Show Location -->
        <label class="control-row">
          <span>Show Location</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={showLocation}
              on:change={saveSettings}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>

        <!-- Client Public Key Display -->
        {#if clientPublicKey}
          <div class="control-row key-display">
            <span>Your Key</span>
            <span class="key-value" title={clientPublicKey}>
              {clientPublicKey.slice(0, 8)}...{clientPublicKey.slice(-4)}
            </span>
          </div>
        {/if}

        <!-- Theme Switcher -->
        <label class="control-row">
          <span>Theme</span>
          <div class="select-wrap">
            <select
              bind:value={currentTheme}
              on:change={saveSettings}
              class="theme-select"
            >
              <option value="light">Light</option>
              <option value="dark">Dark</option>
              <option value="space">Space</option>
            </select>
          </div>
        </label>
      </div>

      <!-- Advanced Features Section -->
      <div class="divider"></div>
      <div class="section-header">Advanced Features</div>
      <div class="options-list">
        <!-- Shield Zero (DGA Threat Detection Engine) -->
        <label class="control-row">
          <span class="sz-label">
            <span class="sz-icon" class:sz-active={neraVaultEnabled}>🛡️</span>
            Shield Zero
          </span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={neraVaultEnabled}
              on:change={toggleNeraVault}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>
        {#if neraVaultEnabled}
          <div class="sz-panel">
            <div class="sz-status">
              <span class="sz-pulse"></span>
              <span class="sz-status-text">Actively hunting threats...</span>
            </div>
            <div class="sz-stats-grid">
              <div class="sz-stat">
                <span class="sz-stat-value"
                  >{shieldZeroStats.session_scanned}</span
                >
                <span class="sz-stat-label">Scanned</span>
              </div>
              <div class="sz-stat sz-stat-danger">
                <span class="sz-stat-value"
                  >{shieldZeroStats.session_blocked}</span
                >
                <span class="sz-stat-label">Blocked</span>
              </div>
              <div class="sz-stat sz-stat-lifetime">
                <span class="sz-stat-value"
                  >{shieldZeroStats.total_blocked}</span
                >
                <span class="sz-stat-label">Lifetime Neutralized</span>
              </div>
              {#if shieldZeroStats.blocklist && shieldZeroStats.blocklist.total_domains > 0}
                <div class="sz-stat sz-stat-blocklist">
                  <span class="sz-stat-value"
                    >{shieldZeroStats.blocklist.total_domains.toLocaleString()}</span
                  >
                  <span class="sz-stat-label">Blocklist Domains</span>
                </div>
              {/if}
            </div>
            {#if shieldZeroThreatLog.length > 0}
              <button
                class="sz-expand-btn"
                on:click={() => (shieldZeroExpanded = !shieldZeroExpanded)}
              >
                {shieldZeroExpanded ? "▼" : "▶"} Threat Log ({shieldZeroThreatLog.length})
              </button>
              {#if shieldZeroExpanded}
                <div class="sz-threat-log">
                  {#each shieldZeroThreatLog as entry}
                    <div
                      class="sz-threat-entry"
                      class:sz-threat-malicious={entry.verdict ===
                        "malicious" || entry.verdict === "blocklist"}
                    >
                      <div class="sz-threat-info">
                        <span class="sz-threat-domain">{entry.domain}</span>
                        <span class="sz-threat-meta">
                          {entry.verdict} · {(entry.score * 100).toFixed(0)}% · {entry.timestamp}
                        </span>
                      </div>
                      <button
                        class="sz-whitelist-btn"
                        title="Whitelist this domain"
                        on:click={() => whitelistDomain(entry.domain)}>✓</button
                      >
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
            {#if shieldZeroWhitelist.length > 0}
              <div class="sz-whitelist-section">
                <span class="sz-whitelist-header"
                  >Whitelisted ({shieldZeroWhitelist.length})</span
                >
                <div class="sz-whitelist-list">
                  {#each shieldZeroWhitelist as domain}
                    <div class="sz-whitelist-chip">
                      <span>{domain}</span>
                      <button
                        class="remove-app"
                        title="Remove"
                        on:click={() => removeWhitelist(domain)}>×</button
                      >
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
          </div>
        {/if}

        <!-- DPI Stealth Mode Toggle -->
        <label class="control-row">
          <span>Obfuscation / DPI Bypass</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={stealthModeEnabled}
              on:change={toggleStealth}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>
        {#if stealthModeEnabled}
          <p class="feature-desc">
            Masks VPN traffic to look like normal web browsing
          </p>
        {/if}

        <!-- Kill Switch -->
        <label class="control-row">
          <span>Kill Switch</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              checked={killswitch}
              on:change={(e) =>
                protection.setKillSwitch(e.currentTarget.checked)}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>

        <!-- Split Tunneling -->
        <label class="control-row">
          <span>Split Tunneling</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={splitTunnelingEnabled}
              on:change={toggleSplitTunneling}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>
        {#if splitTunnelingEnabled}
          <div class="split-tunnel-apps">
            <button class="add-app-btn" on:click={addSplitTunnelApp}>
              + Add App
            </button>
            {#each splitTunnelingApps as app}
              <div class="app-chip">
                <span>{app}</span>
                <button
                  class="remove-app"
                  on:click={() => removeSplitTunnelApp(app)}>×</button
                >
              </div>
            {/each}
          </div>
        {/if}

        <!-- P2P Port Forwarding -->
        <label class="control-row">
          <span>Port Forwarding</span>
          <div class="toggle-wrap">
            <input
              type="checkbox"
              bind:checked={portForwardingEnabled}
              on:change={togglePortForwarding}
              disabled={portToggling}
            />
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
          </div>
        </label>
        {#if portToggling}
          <p class="feature-desc" style="color: #fbbf24;">
            {portForwardingEnabled ? "Activating..." : "Deactivating..."}
          </p>
        {/if}
        {#if portForwardingEnabled && forwardedPort}
          <div class="port-display-row">
            <p class="feature-desc port-display">
              Port: <strong>{forwardedPort}</strong>
            </p>
            <button
              class="port-refresh-btn port-copy-btn"
              on:click={copyPort}
              title={portCopied ? "Copied!" : "Copy port"}
            >
              {#if portCopied}
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#22c55e"
                  stroke-width="2.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              {:else}
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <rect x="9" y="9" width="13" height="13" rx="2" />
                  <path
                    d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"
                  />
                </svg>
              {/if}
            </button>
            <button
              class="port-text-btn"
              on:click={refreshPort}
              disabled={portRefreshing}
              title="Change port"
            >
              {portRefreshing ? "Rotating..." : "Rotate"}
            </button>
          </div>
        {/if}
      </div>

      <div class="divider"></div>
      <button
        class="action-btn text-btn"
        on:click={startRegistration}
        disabled={isBusy}
      >
        Reset Identity
      </button>

      <div class="divider"></div>
      <button
        class="action-btn text-btn"
        on:click={() => (showAboutModal = true)}
      >
        About
      </button>

      <!-- Sign Out at the very bottom with extra spacing -->
      <div class="divider sign-out-divider"></div>
      <button class="action-btn text-btn sign-out-btn" on:click={handleLogout}>
        Sign Out
      </button>
    </div>

    <!-- Top Center: Main Action & Status -->
    <div class="hud-panel top-center">
      <!-- Connect Ring -->
      <div class="ring-wrap">
        <div class={`ring-outer ${vpnStatus === "connected" ? "on" : ""}`}>
          <div class="ring-inner">
            <button
              class={`ring-button ${vpnStatus === "connected" ? "on" : ""}`}
              on:click={toggle}
              disabled={isBusy}
            >
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Bottom Left: Stats & Graph -->
    <div class="hud-panel bottom-left">
      <div class="panel-header">Traffic</div>
      <div class="stats-grid">
        <div class="stat-item">
          <span class="label">DL</span>
          <span class="val">{connected ? downloadSpeed : "—"}</span>
        </div>
        <div class="stat-item">
          <span class="label">UL</span>
          <span class="val">{connected ? uploadSpeed : "—"}</span>
        </div>
        <div class="stat-item">
          <span class="label">Ping</span>
          <span class="val">{connected ? pingValue : "—"}</span>
        </div>
      </div>
    </div>

    <!-- Bottom Center: Graph -->
    <div class="hud-panel bottom-center-graph">
      <div class="traffic-graph">
        <div class="cyber-grid"></div>

        <!-- Peak Label (hover) -->
        <div class="peak-label">Peak: {peakSpeed}</div>

        <svg
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          class="traffic-svg"
        >
          <defs>
            <linearGradient id="trafficGradient" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stop-color="#22c55e" stop-opacity="0.5" />
              <stop offset="100%" stop-color="#22c55e" stop-opacity="0" />
            </linearGradient>
          </defs>

          <!-- Fill Area -->
          <path
            d="{trafficPath} L 100,100 L 0,100 Z"
            fill="url(#trafficGradient)"
            class="traffic-fill"
          />

          <!-- Stroke Line -->
          <path
            d={trafficPath}
            fill="none"
            stroke="#22c55e"
            stroke-width="2"
            vector-effect="non-scaling-stroke"
            stroke-linecap="round"
            stroke-linejoin="round"
            class="traffic-line"
          />
        </svg>
      </div>
    </div>

    <!-- Logic Only: Protection Component (Hidden UI) -->
    <div style="display: none;">
      <Protection
        bind:this={protection}
        bind:vpnConnected={connected}
        bind:killSwitchEnabled={killswitch}
        bind:recoveryMode={recovery}
        bind:error={vpnError}
        autoConnect={autoConnectWifi}
      />
    </div>

    {#if recovery}
      <div class="ks-banner">⚠️ Kill Switch Active</div>
    {/if}
    {#if vpnError}
      <div class="error-toast">{vpnError}</div>
    {/if}
  {:else}
    <!-- State 3: Guest (Show Token Redemption) -->
    <div class="guest-container">
      <RedeemToken />
    </div>
  {/if}

  {#if showRegenModal}
    <div class="modal-backdrop" on:click={() => (showRegenModal = false)}>
      <div class="modal regen-modal" on:click|stopPropagation>
        <div class="regen-icon">⚠️</div>
        <h3>Reset Your Identity?</h3>
        <p class="sub-text">
          This will <strong>destroy your current cryptographic identity</strong>
          and disconnect the VPN. Your browsing history under this key becomes permanently
          unlinkable to your new identity.
        </p>
        <p class="sub-text" style="color: #fbbf24; margin-top: 0.75rem;">
          You will need to re-enter your <strong>Subscription Code</strong> to get
          a new identity.
        </p>
        <div class="regen-actions">
          <button class="regen-cancel" on:click={() => (showRegenModal = false)}
            >Cancel</button
          >
          <button class="regen-confirm" on:click={confirmRegenKey}
            >I Have My Code Ready</button
          >
        </div>
      </div>
    </div>
  {/if}

  {#if showAboutModal}
    <div class="modal-backdrop" on:click={() => (showAboutModal = false)}>
      <div class="modal" on:click|stopPropagation>
        <h3>About Nera VPN™</h3>
        <p>Version 1.0.0</p>
        <div class="divider"></div>
        <p class="sub-text">
          Copyright © 2025 Vio Holdings LLC. All rights reserved.
        </p>
        <p class="sub-text">Nera VPN™ is a trademark of Vio Holdings LLC.</p>
        <p class="sub-text">
          Proprietary software – unauthorized distribution prohibited.
        </p>
        <button
          class="text-btn"
          style="margin-top: 1rem;"
          on:click={() => (showAboutModal = false)}>Close</button
        >
      </div>
    </div>
  {/if}
</main>

<style>
  /* Auth Loading Screen */
  .auth-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    color: white;
  }
  .spinner {
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top: 3px solid #22c55e;
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }
  @keyframes spin {
    0% {
      transform: rotate(0deg);
    }
    100% {
      transform: rotate(360deg);
    }
  }

  /* Guest Container */
  .guest-container {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    width: 100%;
    backdrop-filter: blur(5px);
  }

  /* ... rest of existing styles ... */
  :global(body) {
    margin: 0;
    padding: 0;
    /* Theme Variables */
    --bg-color: #020617;
    --panel-bg: rgba(2, 6, 23, 0.3);
    --border-color: rgba(148, 163, 184, 0.2);
    --text-color: #e2e8f0;
    --text-muted: #94a3b8;
    --accent-cyan: #22d3ee;
    --accent-green: #22c55e;
    --card-hover-bg: rgba(2, 6, 23, 0.3);

    background: var(--bg-image, var(--bg-color)) no-repeat center center fixed;
    background-size: cover;
    font-family:
      system-ui,
      -apple-system,
      sans-serif;
    color: var(--text-color);
    overflow: hidden;
    transition:
      background 0.3s,
      color 0.3s;
  }

  :global(body.theme-dark) {
    --bg-color: #000000;
    --panel-bg: rgba(20, 20, 20, 0.85);
    --border-color: rgba(60, 60, 60, 0.6);
    --text-color: #ffffff;
    --text-muted: #a3a3a3;
    --card-hover-bg: rgba(40, 40, 40, 0.8);
    /* Accents stay vibrant */
  }

  :global(body.theme-space) {
    /* Image Background */
    --bg-color: #000000;
    --bg-image: url("/src/assets/space-bg.png");

    /* Glassy Panels */
    --panel-bg: rgba(10, 10, 15, 0.4);
    --border-color: rgba(100, 100, 255, 0.15);

    /* Text & Accents - Crisp White/Cyan */
    --text-color: #f8fafc;
    --text-muted: #cbd5e1;
    --accent-cyan: #67e8f9;
    --accent-green: #4ade80;
  }

  :global(body.theme-galaxy) {
    /* Image Background */
    --bg-color: #0d0d15;
    --bg-image: url("/src/assets/galaxy-bg.png");

    /* Glassy Panels */
    --panel-bg: rgba(20, 15, 25, 0.4);
    --border-color: rgba(255, 100, 200, 0.15);

    /* Text & Accents - Pink/Purple */
    --text-color: #fdf2f8;
    --text-muted: #e2e8f0;
    --accent-cyan: #f472b6;
    --accent-green: #c084fc;
  }

  main {
    position: relative;
    width: 100vw;
    height: 100vh;
    overflow: hidden;
  }

  /* Background */
  .background {
    position: fixed;
    inset: 0;
    pointer-events: auto;
    z-index: 0;
  }
  .glow {
    position: absolute;
    pointer-events: none;
    border-radius: 999px;
    filter: blur(80px);
    opacity: 0.3;
    z-index: 1;
  }
  .glow-top {
    width: 400px;
    height: 400px;
    background: #22d3ee;
    top: -100px;
    left: -100px;
  }
  .glow-bottom {
    width: 400px;
    height: 400px;
    background: #22c55e;
    bottom: -100px;
    right: -100px;
  }

  /* HUD Panels */
  .hud-panel {
    position: absolute;
    background: var(--panel-bg);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border-color);
    border-radius: 20px;
    padding: 1.2rem;
    z-index: 10;
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    transition:
      background 0.3s,
      border-color 0.3s;
  }

  /* .panel-header moved to local scope to handle icon layout */

  .divider {
    height: 1px;
    background: var(--border-color);
    margin: 1rem 0;
  }

  /* Top Left: IP Display */
  .top-left {
    top: 42px; /* 10px gap below 32px title bar */
    left: 24px;
    padding: 0.6rem 1rem;
    /* Removed min-width to avoid unused space */
  }
  .ip-display {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .ip-row {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }
  .ip-label {
    font-size: 0.65rem;
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.05em;
  }
  .ip-value {
    font-family: monospace;
    font-size: 0.95rem;
    color: var(--accent-cyan);
    font-weight: 600;
  }
  .location-row {
    font-size: 0.8rem;
    color: #cbd5e1;
    margin-top: 2px;
  }
  .location-icon {
    font-size: 0.8rem;
  }
  .ip-error {
    color: #ef4444;
    font-size: 0.7rem;
    font-weight: 600;
  }
  .split-tunnel-row {
    border-left: 2px solid #22c55e;
    padding-left: 0.5rem;
    margin-top: 2px;
    animation: fadeInSplit 0.4s ease-out;
  }
  .split-label {
    color: #22c55e !important;
    font-size: 0.6rem !important;
  }
  .split-value {
    color: #86efac !important;
    font-size: 0.85rem !important;
  }
  @keyframes fadeInSplit {
    from {
      opacity: 0;
      transform: translateX(-4px);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }
  .stealth-badge {
    display: inline-block;
    margin-left: 0.5rem;
    padding: 0.1rem 0.4rem;
    font-size: 0.55rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: #22c55e;
    background: rgba(34, 197, 94, 0.12);
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 4px;
    animation: stealthPulse 2s ease-in-out infinite;
  }
  @keyframes stealthPulse {
    0%,
    100% {
      box-shadow: 0 0 4px rgba(34, 197, 94, 0.2);
    }
    50% {
      box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
    }
  }

  /* Bottom Right: Brand */
  .bottom-right {
    bottom: 24px;
    right: 24px;
    padding: 0.6rem 1rem;
  }
  .brand-row {
    display: flex;
    align-items: center;
    gap: 0.8rem;
  }

  .brand-status {
    margin: 0;
    font-size: 0.7rem;
    color: #94a3b8;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #ef4444;
    display: inline-block;
  }
  .status-dot.on {
    background: #22c55e;
    box-shadow: 0 0 6px rgba(34, 197, 94, 0.6);
  }
  .copyright-footer {
    display: none; /* Safely hide/remove old styles if present */
  }

  /* Top Right: Routes Panel */
  .top-right-routes {
    top: 42px; /* 10px gap below 32px title bar */
    right: 94px; /* 24px + 60px + 10px gap */
    width: 60px;
    max-height: 60px;
    overflow: hidden;
    transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
    white-space: nowrap;
    cursor: pointer;
    z-index: 100; /* Above others if needed */

    /* Collapsed stealth */
    background: transparent;
    border-color: transparent;
    box-shadow: none;
    backdrop-filter: none;
    padding: 1.2rem;
  }
  .top-right-routes:hover {
    width: 260px;
    max-height: 500px; /* Expand to fit content */

    /* Expanded states */
    /* Expanded states */
    background: var(--panel-bg);
    border-color: var(--border-color);
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(20px);
  }

  /* Fade content in/out */
  .route-content {
    opacity: 0;
    transition: opacity 0.2s;
    pointer-events: none;
    margin-top: 1rem;
  }
  .top-right-routes:hover .route-content,
  .top-right-routes:hover .header-title {
    opacity: 1;
    transition-delay: 0.1s;
    pointer-events: auto;
  }

  /* Reuse header title fade from .top-right rule or just duplicate it for safety */
  .top-right-routes .header-title {
    opacity: 0;
    transition: opacity 0.2s;
  }

  .route-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  /* Top Right: Routes Panel */
  .top-right-routes {
    top: 42px; /* 10px gap below 32px title bar */
    right: 140px; /* Moved left to avoid overlapping Session Controls (which acts as ~100px wide with padding) */
    width: 60px;
    max-height: 60px;
    overflow: hidden;
    transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
    white-space: nowrap;
    cursor: pointer;
    z-index: 100; /* Above others if needed */

    /* Collapsed stealth */
    background: transparent;
    border-color: transparent;
    box-shadow: none;
    backdrop-filter: none;
    padding: 1.2rem;
  }
  .top-right-routes:hover {
    width: 210px; /* Thinner to avoid blocking */
    max-height: 500px; /* Expand to fit content */

    /* Expanded states */
    background: rgba(2, 6, 23, 0.3);
    border-color: rgba(148, 163, 184, 0.2);
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(20px);
  }

  /* Fade content in/out */
  .route-content {
    opacity: 0;
    transition: opacity 0.2s;
    pointer-events: none;
    margin-top: 1rem;
  }
  .top-right-routes:hover .route-content,
  .top-right-routes:hover .header-title {
    opacity: 1;
    transition-delay: 0.1s;
    pointer-events: auto;
  }

  /* Reuse header title fade from .top-right rule or just duplicate it for safety */
  .top-right-routes .header-title {
    opacity: 0;
    transition: opacity 0.2s;
  }

  /* Prevent obstruction: Hide Locations icon when Session Controls are expanded */
  main:has(.top-right:hover) .top-right-routes {
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.1s;
  }

  .route-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  /* Top Right: Controls */
  .top-right {
    top: 42px; /* 10px gap below 32px title bar */
    right: 24px;
    width: 60px;
    max-height: 60px;
    overflow: hidden;
    transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
    white-space: nowrap;
    cursor: pointer;

    /* Collapsed: Transparent (Icon only) */
    background: transparent;
    border-color: transparent;
    box-shadow: none;
    backdrop-filter: none;
    padding: 1.2rem; /* Keep padding to position icon stably */
  }
  .top-right:hover {
    width: 320px;
    max-height: 600px;

    /* Expanded: Restore HUD styles */
    background: rgba(2, 6, 23, 0.3);
    border-color: rgba(148, 163, 184, 0.2);
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(20px);
  }

  .panel-header {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #94a3b8;
    margin-bottom: 0.8rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 1rem; /* Space between icon and text */
  }
  .header-icon {
    width: 24px;
    height: 24px;
    min-width: 24px; /* Prevent shrink */
    color: #cbd5e1;
  }
  .header-title {
    opacity: 0;
    transition: opacity 0.2s;
  }
  .top-right:hover .header-title {
    opacity: 1;
    transition-delay: 0.1s;
  }
  /* Move controls layout to avoid ugliness when collapsed... actually overflow hidden should handle it */
  .options-list,
  .action-btn,
  .route-wrapper,
  .divider {
    opacity: 0;
    transition: opacity 0.2s;
    pointer-events: none; /* unexpected clicks */
  }
  .top-right:hover .options-list,
  .top-right:hover .action-btn,
  .top-right:hover .route-wrapper,
  .top-right:hover .divider {
    opacity: 1;
    transition-delay: 0.1s;
    pointer-events: auto;
  }
  .control-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
    color: #cbd5e1;
    margin-bottom: 0.6rem;
    cursor: pointer;
  }
  .toggle-wrap {
    position: relative;
    width: 36px;
    height: 20px;
  }
  .toggle-wrap input {
    opacity: 0;
    width: 0;
    height: 0;
  }
  .theme-select {
    width: 100%;
    background: transparent;
    color: var(--text-color);
    border: none;
    font-size: 0.8rem;
    outline: none;
    cursor: pointer;
  }
  .theme-select option {
    background: #020617; /* Always dark bg for dropdown */
    color: #e2e8f0;
  }
  .toggle-track {
    position: absolute;
    inset: 0;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 20px;
    transition: 0.3s;
  }
  .toggle-thumb {
    position: absolute;
    height: 16px;
    width: 16px;
    left: 2px;
    bottom: 2px;
    background: var(--text-muted);
    border-radius: 50%;
    transition: 0.3s;
  }
  input:checked + .toggle-track {
    background: rgba(34, 197, 94, 0.2);
    border: 1px solid rgba(34, 197, 94, 0.5);
  }
  input:checked + .toggle-track .toggle-thumb {
    transform: translateX(16px);
    background: var(--accent-green);
  }
  .action-btn {
    width: 100%;
    padding: 0.6rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.8rem;
    transition: background 0.2s;
  }
  .action-btn:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.1);
  }
  .status-msg {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-align: center;
    margin-top: 0.5rem;
  }

  /* Bottom Left: Traffic */
  .bottom-left {
    bottom: 24px;
    left: 24px;
    width: auto; /* Shrink to fit stats */
    min-width: 140px;
  }
  .stats-grid {
    display: flex;
    gap: 1.5rem; /* Wider spacing */
    margin-bottom: 0; /* No graph below */
  }

  /* Bottom Center: Graph */
  .bottom-center-graph {
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    width: 400px;
    height: 80px;
    padding: 0; /* Flush graph */
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 1px solid rgba(148, 163, 184, 0.3);
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.6);
  }
  .stat-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .stat-item .label {
    font-size: 0.7rem;
    color: #64748b;
  }
  .stat-item .val {
    font-size: 0.85rem;
    color: #e2e8f0;
    font-family: monospace;
  }
  .traffic-graph {
    width: 100%;
    height: 100%; /* Fill panel */
    margin-bottom: 0;
    overflow: hidden;
    position: relative;
    border-radius: 0;
    background: rgba(0, 0, 0, 0.3);
  }
  .cyber-grid {
    position: absolute;
    inset: 0;
    /* Cyber grid pattern */
    background-image: linear-gradient(
        rgba(34, 197, 94, 0.05) 1px,
        transparent 1px
      ),
      linear-gradient(90deg, rgba(34, 197, 94, 0.05) 1px, transparent 1px);
    background-size: 20px 20px;
    background-position: 0 0;
    transition: opacity 0.3s;
    animation: gridScroll 10s linear infinite;
    z-index: 0;
    mask-image: linear-gradient(
      to bottom,
      transparent,
      black 20%,
      black 80%,
      transparent
    );
    -webkit-mask-image: linear-gradient(
      to bottom,
      transparent,
      black 20%,
      black 80%,
      transparent
    );
  }
  @keyframes gridScroll {
    from {
      background-position: 0 0;
    }
    to {
      background-position: -20px 0;
    }
  }

  .traffic-svg {
    width: 100%;
    height: 100%;
    overflow: visible; /* Allow glow to spill */
    position: relative;
    z-index: 1;
  }
  .traffic-fill {
    transition: d 0.6s ease;
    filter: drop-shadow(0 0 4px rgba(34, 197, 94, 0.2));
  }
  .traffic-line {
    transition: d 0.6s ease;
    filter: drop-shadow(0 0 5px #22c55e);
    animation: pulseGlow 3s ease-in-out infinite;
  }
  @keyframes pulseGlow {
    0%,
    100% {
      filter: drop-shadow(0 0 5px #22c55e);
      stroke: #22c55e;
    }
    50% {
      filter: drop-shadow(0 0 10px #22c55e);
      stroke: #4ade80;
    }
  }

  .peak-label {
    position: absolute;
    top: 4px;
    right: 6px;
    font-size: 0.65rem;
    color: #86efac;
    background: rgba(6, 78, 59, 0.8);
    padding: 2px 6px;
    border-radius: 4px;
    z-index: 5;
    opacity: 0;
    transform: translateY(-5px);
    transition: all 0.2s ease;
    pointer-events: none;
    border: 1px solid rgba(34, 197, 94, 0.3);
  }
  .traffic-graph:hover .peak-label {
    opacity: 1;
    transform: translateY(0);
  }
  .ip-result {
    font-size: 0.75rem;
    color: #22d3ee;
    text-align: center;
    margin-top: 0.5rem;
  }

  /* Top Center: Main Action */
  .top-center {
    top: 0px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    background: transparent;
    border: none;
    box-shadow: none;
    backdrop-filter: none;
  }

  /* Ring Button */
  .ring-wrap {
    width: 80px;
    height: 80px;
  }
  .ring-outer {
    width: 100%;
    height: 100%;
    border-radius: 999px;
    border: 2px solid rgba(148, 163, 184, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  }
  .ring-outer.on {
    border-color: rgba(34, 197, 94, 0.3);
    box-shadow: 0 0 30px rgba(34, 197, 94, 0.2);
  }
  .ring-inner {
    width: 64px;
    height: 64px;
  }
  .ring-button {
    width: 100%;
    height: 100%;
    border-radius: 999px;
    /* Moon Look: Radial gradient from bright grey to dark slate */
    background: radial-gradient(
      circle at 30% 30%,
      #e2e8f0 0%,
      #94a3b8 20%,
      #475569 60%,
      #1e293b 100%
    );
    border: 1px solid rgba(255, 255, 255, 0.3);
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
    color: #e2e8f0;
    /* Soft moon glow */
    box-shadow:
      0 0 15px rgba(148, 163, 184, 0.3),
      inset 0 2px 5px rgba(255, 255, 255, 0.5);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
  }
  .ring-button:hover:not(:disabled) {
    background: radial-gradient(
      circle at 30% 30%,
      #f1f5f9 0%,
      #cbd5e1 20%,
      #64748b 60%,
      #334155 100%
    );
    box-shadow:
      0 0 20px rgba(148, 163, 184, 0.5),
      inset 0 2px 8px rgba(255, 255, 255, 0.7);
    transform: scale(1.02);
  }
  .ring-button:active:not(:disabled) {
    transform: scale(0.98);
    box-shadow: inset 0 4px 12px rgba(0, 0, 0, 0.4);
  }
  .ring-button.on {
    background: radial-gradient(
      circle,
      var(--accent-green) 0%,
      /* Use var but opacity is tricky here, hardcode OK or use css var with rgb */
        rgba(6, 78, 59, 0.8) 100%
    );
    border: 2px solid #86efac;
    box-shadow:
      0 0 20px #22c55e,
      inset 0 0 15px rgba(34, 197, 94, 0.5);
    color: #ffffff;
    text-shadow: 0 0 8px rgba(255, 255, 255, 0.6);
  }
  .ring-state {
    font-size: 1.6rem;
    font-weight: 700;
  }
  .ring-label {
    font-size: 0.8rem;
    font-weight: 500;
    opacity: 0.8;
  }

  /* Route Selector */
  .route-wrapper {
    position: relative;
  }
  .route-wrapper.full-width {
    width: 100%;
  }
  .route-selector {
    background: rgba(2, 6, 23, 0.6);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #e2e8f0;
    padding: 0.6rem 1rem;
    border-radius: 12px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.8rem;
    font-size: 0.9rem;
    width: 100%;
  }
  .route-selector .val {
    flex: 1;
    text-align: left;
  }
  .chevron {
    font-size: 0.6rem;
    color: #94a3b8;
  }
  .route-menu {
    position: absolute;
    top: 110%; /* Open downwards */
    right: 0;
    width: 100%;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 12px;
    padding: 0.5rem;
    backdrop-filter: blur(20px);
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    z-index: 20;
  }
  .route-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.5rem;
    background: transparent;
    border: none;
    color: #cbd5e1;
    font-size: 0.85rem;
    cursor: pointer;
    border-radius: 6px;
    text-align: left;
  }
  .route-item:hover {
    background: rgba(255, 255, 255, 0.05);
  }
  .route-dot {
    width: 6px;
    height: 6px;
    background: #475569;
    border-radius: 50%;
  }
  .route-dot.active {
    background: #22c55e;
  }
  .route-label {
    flex: 1;
  }
  .check {
    color: #22c55e;
    font-size: 0.8rem;
  }

  /* Banners */
  .ks-banner {
    position: absolute;
    top: 100px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(239, 68, 68, 0.9);
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-weight: 500;
    z-index: 20;
    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
  }
  .error-toast {
    position: absolute;
    bottom: 100px;
    left: 50%;
    transform: translateX(-50%);
    background: #ef4444;
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.8rem;
    z-index: 20;
  }

  /* Port Refresh Button */
  .port-refresh-btn {
    background: transparent;
    border: 1px solid rgba(100, 116, 139, 0.3);
    border-radius: 6px;
    color: #94a3b8;
    width: 28px;
    height: 28px;
    padding: 4px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s ease;
  }
  .port-refresh-btn:hover:not(:disabled) {
    color: #22d3ee;
    border-color: rgba(34, 211, 238, 0.4);
    background: rgba(34, 211, 238, 0.08);
  }
  .port-refresh-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .port-refresh-btn svg {
    width: 16px;
    height: 16px;
  }

  /* Port Text Button (Rotate) */
  .port-text-btn {
    background: transparent;
    border: none;
    color: #22d3ee;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 4px;
    transition: all 0.2s ease;
  }
  .port-text-btn:hover:not(:disabled) {
    background: rgba(34, 211, 238, 0.1);
  }
  .port-text-btn:disabled {
    color: #fbbf24;
    opacity: 0.8;
    cursor: not-allowed;
  }

  /* Copy button snugs up next to port number */
  .port-copy-btn {
    border: none;
    background: transparent;
    margin-left: -8px; /* Pull it closer */
    padding: 4px; /* Larger touch area */
    width: 26px;
    height: 26px;
    border-radius: 6px;
    color: #94a3b8;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s ease;
  }
  .port-copy-btn:hover {
    color: #22d3ee;
    background: rgba(34, 211, 238, 0.1);
  }

  /* Port Display Text */
  .port-display {
    margin-right: 0 !important; /* Force no gap on the right */
  }

  /* Modal Styles */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(5px);
    z-index: 2000;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .modal {
    background: #0f172a;
    border: 1px solid #334155;
    padding: 2rem;
    border-radius: 12px;
    text-align: center;
    min-width: 300px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
  }

  /* Regen Identity Modal */
  .regen-icon {
    font-size: 2.5rem;
    margin-bottom: 0.75rem;
  }
  .regen-modal h3 {
    color: #f1f5f9;
    margin: 0 0 0.75rem;
  }
  .regen-modal .sub-text {
    font-size: 0.85rem;
    line-height: 1.5;
  }
  .regen-actions {
    display: flex;
    gap: 0.75rem;
    margin-top: 1.5rem;
    justify-content: center;
  }
  .regen-cancel {
    padding: 0.6rem 1.2rem;
    border-radius: 8px;
    border: 1px solid #475569;
    background: transparent;
    color: #94a3b8;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .regen-cancel:hover {
    background: rgba(100, 116, 139, 0.2);
    color: #e2e8f0;
  }
  .regen-confirm {
    padding: 0.6rem 1.2rem;
    border-radius: 8px;
    border: none;
    background: linear-gradient(135deg, #ef4444, #dc2626);
    color: white;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
  }
  .regen-confirm:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(239, 68, 68, 0.4);
  }
  .spinner {
    width: 24px;
    height: 24px;
    border: 3px solid #22d3ee; /* Cyan */
    border-top-color: transparent;
    border-radius: 50%;
    margin: 1rem auto;
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .sub-text {
    color: #64748b;
    font-size: 0.85rem;
    margin-top: 0.5rem;
  }
  .icon-success {
    font-size: 2rem;
    color: #22c55e;
    margin-bottom: 0.5rem;
  }
  .icon-error {
    font-size: 2rem;
    color: #ef4444;
    margin-bottom: 0.5rem;
  }
  .error-msg {
    color: #ef4444;
    font-size: 0.85rem;
    margin: 0.5rem 0;
  }
  .retry-btn {
    background: #22d3ee;
    color: #0f172a;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 1rem;
  }
  .text-btn {
    background: none;
    border: none;
    color: #94a3b8;
    cursor: pointer;
    font-size: 0.8rem;
    margin-top: 0.5rem;
    width: 100%;
    text-align: center;
    display: block;
  }
  .text-btn:hover {
    color: #e2e8f0;
  }

  /* Change Server Button */
  .change-server-btn {
    width: 100%;
    padding: 0.6rem 1rem;
    margin-bottom: 0.8rem;
    background: linear-gradient(135deg, #22d3ee 0%, #0891b2 100%);
    color: #0f172a;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: 0 2px 10px rgba(34, 211, 238, 0.3);
  }
  .change-server-btn:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(34, 211, 238, 0.4);
  }
  .change-server-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* Smart Connect Item */
  .smart-connect-item {
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 0.3rem;
    padding-bottom: 0.5rem;
  }
  .route-dot.smart {
    background: linear-gradient(135deg, #fbbf24 0%, #f97316 100%) !important;
    box-shadow: 0 0 8px rgba(251, 191, 36, 0.5);
  }

  /* Sign Out Styling */
  .sign-out-divider {
    margin-top: 1rem;
  }
  .sign-out-btn {
    color: #ef4444 !important;
    margin-top: 0.5rem;
    width: 100%;
    text-align: center;
    display: block;
  }
  .sign-out-btn:hover {
    color: #f87171 !important;
  }

  /* Connection Status HUD */
  .status-hud {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0; /* Flush */
  }

  /* Specific styling for top-left to be more flush */
  .hud-panel.top-left {
    padding: 0.8rem 1.2rem; /* Reduced vertical padding */
  }

  .status-text {
    color: #94a3b8;
    font-size: 0.85rem;
    font-weight: 500;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #ef4444; /* Default inactive */
    box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
    transition: all 0.3s ease;
  }
  .status-dot.green {
    background: #22c55e;
    box-shadow: 0 0 10px rgba(34, 197, 94, 0.6);
  }
  .status-dot.yellow {
    background: #eab308;
    box-shadow: 0 0 10px rgba(234, 179, 8, 0.6);
  }
  .status-dot.red {
    background: #ef4444;
    box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
  }
  .animate-pulse {
    animation: statusPulse 1.5s infinite ease-in-out;
  }
  @keyframes statusPulse {
    0% {
      transform: scale(1);
      opacity: 1;
    }
    50% {
      transform: scale(1.2);
      opacity: 0.8;
    }
    100% {
      transform: scale(1);
      opacity: 1;
    }
  }

  /* Client Public Key Display */
  .key-display {
    border-top: 1px solid rgba(100, 116, 139, 0.2);
    padding-top: 0.5rem;
    margin-top: 0.25rem;
  }
  .key-value {
    font-family: monospace;
    font-size: 0.75rem;
    color: #22d3ee;
    background: rgba(34, 211, 238, 0.1);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    cursor: pointer;
  }
  .key-value:hover {
    background: rgba(34, 211, 238, 0.2);
  }

  /* Advanced Features Styling */
  .section-header {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #64748b;
    margin: 0.8rem 0 0.5rem 0;
    font-weight: 600;
  }

  .feature-desc {
    font-size: 0.75rem;
    color: #64748b;
    margin: 0.25rem 0 0.5rem 0;
    padding-left: 0.5rem;
    border-left: 2px solid #22d3ee;
  }

  .port-display strong {
    color: #22c55e;
    font-family: monospace;
    font-size: 0.9rem;
  }

  .port-display-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
  }

  .port-refresh-btn {
    background: transparent;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.8rem;
    padding: 0.15rem 0.4rem;
    transition: all 0.2s ease;
    line-height: 1;
  }

  .port-refresh-btn:hover:not(:disabled) {
    background: rgba(34, 211, 238, 0.1);
    border-color: #22d3ee;
  }

  .port-refresh-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .split-tunnel-apps {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin: 0.5rem 0;
  }

  .add-app-btn {
    background: rgba(34, 211, 238, 0.1);
    border: 1px dashed #22d3ee;
    color: #22d3ee;
    padding: 0.3rem 0.6rem;
    border-radius: 6px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s ease;
  }
  .add-app-btn:hover {
    background: rgba(34, 211, 238, 0.2);
  }

  .app-chip {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    background: rgba(100, 116, 139, 0.2);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    color: #94a3b8;
  }
  .app-chip span {
    max-width: 100px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .remove-app {
    background: none;
    border: none;
    color: #ef4444;
    cursor: pointer;
    font-size: 0.9rem;
    line-height: 1;
    padding: 0;
  }
  .remove-app:hover {
    color: #f87171;
  }

  /* ─── Shield Zero Panel ─────────────────────────── */
  .sz-label {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .sz-icon {
    font-size: 1.1rem;
    filter: grayscale(1) opacity(0.5);
    transition: all 0.3s ease;
  }
  .sz-icon.sz-active {
    filter: none;
    animation: sz-glow 2s ease-in-out infinite;
  }
  @keyframes sz-glow {
    0%,
    100% {
      filter: drop-shadow(0 0 2px rgba(34, 211, 238, 0.4));
    }
    50% {
      filter: drop-shadow(0 0 8px rgba(34, 211, 238, 0.8));
    }
  }

  .sz-panel {
    background: rgba(34, 211, 238, 0.05);
    border: 1px solid rgba(34, 211, 238, 0.15);
    border-radius: 10px;
    padding: 0.75rem;
    margin: 0.4rem 0 0.6rem;
    animation: sz-fadein 0.3s ease;
  }
  @keyframes sz-fadein {
    from {
      opacity: 0;
      transform: translateY(-8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .sz-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.6rem;
  }
  .sz-pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #22c55e;
    animation: sz-pulse-anim 1.5s ease-in-out infinite;
  }
  @keyframes sz-pulse-anim {
    0%,
    100% {
      box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.6);
    }
    50% {
      box-shadow: 0 0 0 6px rgba(34, 197, 94, 0);
    }
  }
  .sz-status-text {
    font-size: 0.72rem;
    color: #22c55e;
    font-weight: 500;
    letter-spacing: 0.02em;
  }

  .sz-stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .sz-stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    background: rgba(100, 116, 139, 0.12);
    border-radius: 8px;
    padding: 0.5rem 0.3rem;
  }
  .sz-stat-value {
    font-size: 1.2rem;
    font-weight: 700;
    color: #22d3ee;
    font-variant-numeric: tabular-nums;
  }
  .sz-stat-danger .sz-stat-value {
    color: #ef4444;
  }
  .sz-stat-lifetime .sz-stat-value {
    color: #f59e0b;
  }
  .sz-stat-blocklist .sz-stat-value {
    color: #3b82f6;
  }
  .sz-stat-label {
    font-size: 0.62rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.15rem;
  }

  .sz-expand-btn {
    background: none;
    border: none;
    color: #94a3b8;
    font-size: 0.72rem;
    cursor: pointer;
    padding: 0.3rem 0;
    transition: color 0.2s;
    width: 100%;
    text-align: left;
  }
  .sz-expand-btn:hover {
    color: #e2e8f0;
  }

  .sz-threat-log {
    max-height: 150px;
    overflow-y: auto;
    margin-top: 0.3rem;
  }
  .sz-threat-entry {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.3rem 0.4rem;
    border-radius: 6px;
    margin-bottom: 0.2rem;
    background: rgba(100, 116, 139, 0.08);
    transition: background 0.2s;
  }
  .sz-threat-entry:hover {
    background: rgba(100, 116, 139, 0.18);
  }
  .sz-threat-malicious {
    border-left: 2px solid #ef4444;
    background: rgba(239, 68, 68, 0.06);
  }
  .sz-threat-info {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .sz-threat-domain {
    font-size: 0.72rem;
    color: #e2e8f0;
    font-family: "JetBrains Mono", monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .sz-threat-meta {
    font-size: 0.6rem;
    color: #64748b;
  }
  .sz-whitelist-btn {
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    color: #22c55e;
    border-radius: 4px;
    width: 22px;
    height: 22px;
    font-size: 0.7rem;
    cursor: pointer;
    transition: all 0.2s;
    flex-shrink: 0;
  }
  .sz-whitelist-btn:hover {
    background: rgba(34, 197, 94, 0.25);
  }

  .sz-whitelist-section {
    margin-top: 0.5rem;
    padding-top: 0.4rem;
    border-top: 1px solid rgba(100, 116, 139, 0.15);
  }
  .sz-whitelist-header {
    font-size: 0.65rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .sz-whitelist-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    margin-top: 0.3rem;
  }
  .sz-whitelist-chip {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    background: rgba(34, 197, 94, 0.08);
    border: 1px solid rgba(34, 197, 94, 0.2);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.65rem;
    color: #86efac;
  }
</style>
