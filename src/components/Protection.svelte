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
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";

  // --- Exposed State ---
  export let vpnConnected = false;
  export let killSwitchEnabled = false;
  export let recoveryMode = false;
  export let error = "";
  export let autoConnect = false;

  // --- Public Actions ---
  export const connect = async (serverKey = null) => {
    error = "";
    try {
      // Get the stored access token
      const accessToken = await invoke("get_access_token");
      if (!accessToken) {
        error =
          "No access token found. Please redeem a subscription code first.";
        return;
      }

      // Use the new token-based connection
      const serverId =
        serverKey || (await invoke("get_selected_server")) || "tokyo";
      await invoke("connect_with_token", {
        serverId: serverId,
        accessToken: accessToken,
      });

      // Manually update state since new command doesn't emit events yet
      vpnConnected = true;
    } catch (e) {
      console.error("Connect failed", e);
      error = String(e);
    }
  };

  export const disconnect = async () => {
    error = "";
    try {
      // Try both disconnect methods for compatibility
      await invoke("disconnect_token_vpn").catch(() => {});
      await invoke("disconnect_vpn").catch(() => {});
      vpnConnected = false;
    } catch (e) {
      console.error("Disconnect failed", e);
      error = String(e);
    }
  };

  export const setKillSwitch = async (enabled) => {
    error = "";
    try {
      await invoke("set_kill_switch", { enabled });
    } catch (e) {
      console.error("Set Kill Switch failed", e);
      error = String(e);
    }
  };

  // --- Internal ---
  let unlistenStatus;
  let unlistenKS;

  $: recoveryMode = killSwitchEnabled && !vpnConnected;

  onMount(async () => {
    // 1. Register listeners first to ensure we catch any events triggered by subsequent actions
    unlistenStatus = await listen("vpn-status-changed", (e) => {
      vpnConnected = e.payload.connected;
    });

    unlistenKS = await listen("kill-switch-changed", (e) => {
      killSwitchEnabled = e.payload.enabled;
    });

    try {
      // 2. Fetch initial state
      vpnConnected = await invoke("get_vpn_status");
      killSwitchEnabled = await invoke("get_kill_switch_status");

      // 3. Trigger auto-connect if needed
      // Note: Auto-connect currently doesn't know *which* server was selected if we don't pass it.
      // But connect() defaults to null.
      // However, App.svelte passes serverKey.
      // Protection doesn't track selected server itself.
      // Ideally Protection should ask backend "what is selected?" if it needs to connect blindly.
      // OR, App.svelte handles the auto-connect logic?
      // We moved auto-connect logic HERE.
      // If we call connect() without args, backend received None -> defaults to "tokyo".
      // But if user selected "London" (saved in backend), connect(None) -> "tokyo" (hardcoded default in internal)?
      // INTERNAL LOGIC: `let key = server_key.unwrap_or_else(|| "tokyo".to_string());`
      // So if we send None, it defaults to Tokyo.
      // BUT `get_selected_server` exists.
      // Protection should fetching selected server before auto-connecting?
      // Or we update `connect_vpn_internal` to `unwrap_or_else(|| load_settings().selected_server)`?
      // That would be smarter.
      // Let's rely on backend smarts or fetch it here.
      // Checking backend... `connect_vpn_internal` takes `server_key: Option<String>`.
      // `let key = server_key.unwrap_or_else(|| "tokyo".to_string());` -> This is static default.
      // I should update backend to use saved setting if None is passed?
      // OR I fetch it here.
      // Fetching here is safer for now without changing backend again immediately.
      if (autoConnect && !vpnConnected) {
        try {
          const savedKey = await invoke("get_selected_server");
          connect(savedKey);
        } catch {
          connect(); // fallback
        }
      }
    } catch (e) {
      console.error("Failed to init protection", e);
      error = "Init failed";
    }
  });

  onDestroy(() => {
    if (unlistenStatus) unlistenStatus();
    if (unlistenKS) unlistenKS();
  });
</script>

<slot />
