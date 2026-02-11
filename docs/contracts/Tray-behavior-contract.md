# Tray Behavior Contract — Nera VPN

Version: 1.0
Status: Binding
Applies to:

* Desktop (Windows) — Implemented
* Desktop (macOS) — Planned

---

## Purpose

This document defines the **authoritative behavior of the system tray / menu bar integration** for Nera VPN.

The tray exists as a **safety-critical control surface**, not a convenience UI.

If the main window fails, crashes, or is hidden, the tray **must remain a reliable recovery and control mechanism**.

Any deviation from this contract is a **user safety and security bug**.

---

## Core Principles (Platform-Agnostic)

1. **Tray Is Always Available**

   * The tray must initialize regardless of main window state.
   * Tray failure is a critical error.

2. **Tray Is Backend-Driven**

   * Tray actions call backend logic directly.
   * Tray labels and enabled/disabled states reflect backend state only.

3. **Tray Can Recover the System**

   * The tray must provide a path to restore internet access if the Kill Switch is active.

4. **Tray Has Authority Over UI**

   * The tray may change VPN state even if the main UI is closed or stale.

---

## Required Tray Actions

The tray MUST expose the following actions when applicable:

### Always Visible

* **Open App**

  * Opens or focuses the main window
  * Must not change VPN or Kill Switch state

* **Quit**

  * Initiates graceful shutdown
  * If VPN is connected:

    * Must disconnect VPN before exit
  * Must not silently disable Kill Switch unless explicitly required by Recovery Policy

---

### VPN Control Actions

* **Connect**

  * Visible only when VPN is disconnected
  * Calls backend connect logic

* **Disconnect**

  * Visible only when VPN is connected
  * Calls backend disconnect logic

The tray must never show both actions simultaneously.

---

### Kill Switch & Recovery Actions

* **Disable Kill Switch (Restore Internet)**

  * Visible ONLY when:

    * Kill Switch is enabled AND
    * System is in Recovery Mode
  * Calls backend disable kill switch logic

This action must be:

* Clearly labeled
* One-click
* Always enabled

---

## State-Driven Visibility Rules

Tray menu composition must be derived from backend state:

| Backend State                     | Tray Actions Visible                |
| --------------------------------- | ----------------------------------- |
| VPN Disconnected, Kill Switch Off | Connect, Open App, Quit             |
| VPN Connected, Kill Switch Off    | Disconnect, Open App, Quit          |
| VPN Disconnected, Kill Switch On  | Disable Kill Switch, Open App, Quit |
| VPN Connected, Kill Switch On     | Disconnect, Open App, Quit          |

---

## Error & Uncertain States

If backend state is:

* Unknown
* Desynchronized
* Recovering

The tray must:

* Prefer safety
* Expose recovery actions
* Avoid destructive operations

---

## Windows Implementation (Appendix A — Implemented)

* Uses Tauri SystemTray
* Tray initialized before main window render
* Tray events routed directly to backend commands

Tray logic must not depend on frontend readiness.

---

## macOS Implementation (Appendix B — Planned)

* Uses Menu Bar (Status Item)
* Must mirror Windows tray semantics
* Menu Bar must persist across Spaces and fullscreen apps

---

## Contract Violations (Examples)

The following are violations:

* Tray missing while Kill Switch is active
* Tray Connect button shown while VPN is already connected
* Quit action leaving VPN connected silently
* No recovery option available during blocked internet state

---

## Change Control

Any modification to tray behavior requires:

* Update to this contract
* Review against Backend Firewall Contract
* Validation against Recovery Policy

---

End of Contract
