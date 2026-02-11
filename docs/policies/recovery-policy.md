# Recovery Policy — Nera VPN

Version: 1.0
Status: Binding
Effective: Immediately

Applies to:

* Desktop (Windows) — Implemented
* Desktop (macOS) — Planned
* Mobile (iOS) — Planned
* Mobile (Android) — Planned

---

## Purpose

This document defines **how users recover network access safely** when Nera VPN protection mechanisms (Kill Switch, firewall enforcement) are active or in an uncertain state.

Recovery is treated as a **safety mechanism**, not a convenience feature.

The system must ensure:

* Users are never permanently locked out of the internet
* Recovery does not silently weaken protection guarantees

---

## Core Recovery Principles

### 1. Recovery Must Always Exist

* At least one recovery path must be available at all times
* Recovery must not depend on frontend rendering
* Recovery must remain accessible even if the main UI crashes

---

### 2. Recovery Is Explicit and Intentional

* Recovery actions must be clearly labeled
* Recovery must require deliberate user action
* Accidental recovery is forbidden

---

### 3. Recovery Preserves User Agency

* Users must understand they are restoring internet access
* Recovery must never occur silently or automatically

---

## Recovery Mode

### Definition

Recovery Mode is an enforced state where:

* Kill Switch is enabled
* VPN is disconnected OR backend state is uncertain

---

### Behavior While in Recovery Mode

While Recovery Mode is active:

* Internet access remains blocked
* VPN connection may be re-established
* Kill Switch remains enabled

No automatic downgrade of protection is allowed.

---

## Guaranteed Recovery Channels

At least one of the following must always function:

### 1. System Tray / Menu Bar (Primary)

* Must expose a **"Disable Kill Switch (Restore Internet)"** action
* Action must be:

  * Always enabled
  * One-click
  * Clearly labeled

---

### 2. OS-Level Manual Recovery (Secondary)

If application UI is unavailable, documented manual recovery must exist.

#### Windows (Implemented)

* Close Nera VPN
* Open Administrator PowerShell
* Run:

```
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

---

## Startup Recovery Rules

On application startup:

* Backend must load persisted Kill Switch state
* If enabled:

  * Enforce firewall immediately
  * Enter Recovery Mode
  * Initialize tray recovery action

The user must never boot into an unprotected state unintentionally.

---

## UI Responsibilities During Recovery

While in Recovery Mode, the UI must:

* Display a persistent warning
* Disable ambiguous actions
* Surface recovery intent clearly

UI failure must not block recovery.

---

## Forbidden Recovery Behaviors

The following are forbidden:

* Automatically disabling Kill Switch after timeout
* Hiding recovery actions
* Restoring internet access without user intent
* Requiring advanced technical knowledge to recover

---

## Relationship to Other Policies

This policy works in conjunction with:

* Protection Policy v1.0
* Backend Firewall Contract
* Tray Behavior Contract

If conflicts arise, **Protection Policy v1.0 takes precedence**.

---

## Change Control

Any changes to this policy require:

* Version increment
* Review of lockout and safety scenarios
* Validation against all enforcement contracts

---

End of Recovery Policy
