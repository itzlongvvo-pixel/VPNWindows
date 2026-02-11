# Backend Firewall Contract — Nera VPN

Version: 1.0
Status: Binding
Applies to:

* Desktop (Windows) — Implemented
* Desktop (macOS) — Planned
* Mobile (iOS) — Planned
* Mobile (Android) — Planned

---

## Purpose

This document defines the **non-negotiable guarantees and behaviors** of Nera VPN's backend-enforced firewall and kill switch system.

It exists to ensure that **network safety does not depend on UI state, frontend correctness, or user understanding**.

If backend behavior deviates from this contract, it is considered a **critical security bug**.

---

## Core Security Guarantees (Platform-Agnostic)

The following guarantees MUST hold on all platforms, regardless of implementation details:

1. **Fail-Closed Networking**

   * When Kill Switch is enabled, all non-VPN traffic must be blocked.
   * No UI state, crash, reload, or restart may implicitly disable protection.

2. **Backend Authority**

   * Firewall state is authoritative in the backend.
   * The frontend may only request changes; it may not assume success.

3. **Crash & Restart Persistence**

   * If Kill Switch was active prior to crash/restart, the system must boot into a protected (blocked) state.

4. **Explicit Recovery Path**

   * The user must always have a deliberate, discoverable way to restore internet access.
   * Recovery must not rely on frontend rendering success.

5. **No Silent Downgrade**

   * The backend must never automatically relax firewall rules without an explicit disable request.

---

## Backend State Model

The backend maintains a canonical state structure (conceptual):

* `vpn_connected: bool`
* `kill_switch_enabled: bool`
* `recovery_mode: bool`
* `last_firewall_apply_result: Success | Error`

This state:

* Is owned by the backend
* Is persisted across restarts
* Is emitted to the frontend as read-only events

---

## Windows Implementation (Appendix A — Implemented)

### Enforcement Mechanism

* Uses `netsh advfirewall`
* Modifies **outbound policy**

### When Kill Switch is Enabled

1. Set outbound firewall policy to `Block`
2. Create allow rules for:

   * `wireguard.exe`
   * Nera tunnel interface (e.g. `nera`)
   * Loopback traffic
   * DNS (UDP 53) *only if required*

### When Kill Switch is Disabled

1. Restore outbound policy to `Allow`
2. Remove all Nera-created firewall rules

### Startup Behavior

* On app startup:

  * Load persisted kill switch state
  * If enabled:

    * Apply firewall rules immediately
    * Enter `recovery_mode = true`

---

## Recovery Mode Contract

Recovery Mode exists to prevent user lockout.

### Rules

* Recovery Mode is active when:

  * Kill Switch is enabled
  * VPN is disconnected OR state is uncertain

* While in Recovery Mode:

  * Internet remains blocked
  * A **minimal recovery action** must be available

### Guaranteed Recovery Channels

At least one of the following must always function:

* System tray menu
* OS-level command-line recovery instructions

Frontend rendering failure must NOT block recovery.

---

## Frontend Interaction Rules

The frontend:

* May request:

  * Enable Kill Switch
  * Disable Kill Switch
* Must NOT:

  * Assume firewall state
  * Fake connection indicators
  * Override backend state

All UI indicators must be driven by backend-emitted events.

---

## Logging & Auditability

The backend must log:

* Firewall rule changes
* Kill switch enable/disable requests
* Failures to apply or remove rules

Logs must be retrievable for debugging and support.

---

## macOS & iOS (Appendix B & C — Planned)

### macOS (Planned)

* Enforcement via:

  * `pf` or
  * Network Extension (`NEPacketTunnelProvider`)

* Kill Switch must be enforced inside the tunnel provider

### iOS (Planned)

* Uses Always-On VPN
* No global firewall control
* Kill Switch is a policy constraint, not a packet filter

Exact mechanics will be documented in platform-specific appendices.

---

## Contract Violations (Examples)

The following are violations:

* UI showing "Connected" while firewall is open
* Kill Switch disabling automatically on restart
* Internet restored without explicit user action
* Firewall rules removed due to frontend crash

---

## Change Control

Any modification to this document requires:

* Version bump
* Explicit migration plan
* Review against UI State Contract

---

End of Contract
