# Protection Policy v1.0 — Nera VPN

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

This document defines **Nera VPN’s non-negotiable user protection guarantees**.

It exists to answer one question:

> *What must Nera VPN protect users from — even when they make mistakes?*

This policy governs **backend behavior, UI behavior, tray behavior, and recovery logic**.

If any implementation violates this policy, it is considered a **critical product failure**, not a UX issue.

---

## Core Protection Principles

### 1. Safety Over Convenience

* Security guarantees must not be bypassed for ease of use.
* If there is ambiguity, the system must choose the **safer state**.

---

### 2. No Silent Failure

* The system must never silently:

  * Drop VPN protection
  * Disable the kill switch
  * Restore open internet access

All protection changes must be:

* Explicit
* Observable
* User-initiated

---

### 3. Fail Closed, Not Open

* On crashes, restarts, or unexpected termination:

  * Network traffic must default to **blocked** if protection was previously enabled.

---

### 4. Protection Is Backend-Enforced

* Protection does not depend on:

  * UI correctness
  * Tray rendering
  * User understanding

The backend is the final authority.

---

## Kill Switch Policy

### Definition

The Kill Switch guarantees that **no traffic leaves the device outside the VPN tunnel** when enabled.

---

### Required Behavior

When Kill Switch is enabled:

* All non-VPN traffic must be blocked
* This state must persist across:

  * App restarts
  * System reboots
  * UI reloads

---

### Explicit Disable Requirement

* The Kill Switch must only be disabled by:

  * A deliberate user action
  * A clearly labeled recovery action

Implicit disable is forbidden.

---

## Recovery & Lockout Prevention Policy

### Recovery Mode

Recovery Mode exists to prevent permanent internet lockout.

The system must enter Recovery Mode when:

* Kill Switch is enabled AND
* VPN is disconnected OR state is uncertain

---

### Recovery Guarantees

While in Recovery Mode:

* Internet remains blocked
* At least one recovery path must always exist:

  * System tray / menu bar
  * OS-level manual recovery instructions

Recovery must not rely on frontend rendering.

---

## User Error Protection

The system must protect users from:

* Accidentally enabling Kill Switch without understanding consequences
* Quitting the app while protected
* System restarts during protected states
* UI desynchronization

Protection must persist even if the user is confused.

---

## Application Lifecycle Rules

### Startup

* On launch, the backend must:

  * Load persisted protection state
  * Enforce Kill Switch immediately if enabled
  * Surface recovery options

---

### Shutdown

* On Quit:

  * VPN must disconnect gracefully
  * Kill Switch must remain enabled unless explicitly disabled

---

## Forbidden Behaviors

The following are strictly forbidden:

* Automatically disabling Kill Switch on startup
* Removing firewall rules due to UI failure
* Showing “Connected” while traffic is unprotected
* Leaving the user with no recovery path

---

## Relationship to Other Contracts

This policy is enforced through:

* Backend Firewall Contract
* Tray Behavior Contract
* UI State Contract

If conflicts arise, this document takes precedence.

---

## Change Control

Any changes to this policy require:

* Version increment
* Explicit rationale
* Review of all enforcement contracts

---

End of Protection Policy v1.0
