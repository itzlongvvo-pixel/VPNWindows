# UI State Contract — Nera VPN

Version: 1.0
Status: Binding

Applies to:

* Desktop (Windows) — Implemented
* Desktop (macOS) — Planned
* Mobile (iOS) — Planned
* Mobile (Android) — Planned

---

## Purpose

This document defines the **authoritative mapping between backend protection state and user-visible UI behavior**.

The UI is a *representation* of backend state — never a source of truth.

If the UI contradicts backend state, the UI is considered **incorrect**.

---

## Core Principles

### 1. Backend Is Source of Truth

* UI must only render state received from the backend
* UI must not infer or assume protection status

---

### 2. UI Must Never Lie

* No optimistic states
* No speculative animations
* No "connected" visuals unless confirmed by backend

---

### 3. Safety Over Aesthetics

* Ambiguous states must render conservatively
* Warnings take priority over visuals

---

## Canonical Backend States

The UI reacts to the following backend-owned state values:

* `vpn_connected: bool`
* `kill_switch_enabled: bool`
* `recovery_mode: bool`
* `error: Option<Error>`

These values are emitted via events and queryable on UI mount.

---

## Canonical UI States

The UI MUST map backend state into **exactly one** of the following UI states.

---

### 1. Disconnected (Unprotected)

**Conditions**

* `vpn_connected = false`
* `kill_switch_enabled = false`

**UI Requirements**

* Status: "Not Connected"
* Primary action: **Connect**
* Kill Switch toggle: OFF (enabled)
* No warning banners

---

### 2. Connected (Protected)

**Conditions**

* `vpn_connected = true`

**UI Requirements**

* Status: "Connected"
* Primary action: **Disconnect**
* Kill Switch toggle: reflects backend value
* No warning banners

---

### 3. Recovery Mode (Blocked)

**Conditions**

* `kill_switch_enabled = true` AND
* `vpn_connected = false`

**UI Requirements**

* Status: "Kill Switch Active"
* Persistent warning banner: "Internet Blocked"
* Primary action: **Connect VPN**
* Secondary action: **Disable Kill Switch (Restore Internet)**
* Disable ambiguous actions

---

### 4. Protected + Kill Switch

**Conditions**

* `vpn_connected = true`
* `kill_switch_enabled = true`

**UI Requirements**

* Status: "Connected"
* Kill Switch indicator: ON
* No recovery banner

---

### 5. Error State

**Conditions**

* `error != None`

**UI Requirements**

* Status: "Connection Error"
* Display error message
* Do NOT alter backend state automatically
* Preserve last known protection state

---

## State Transition Rules

* UI state may only change in response to backend events
* UI must re-query backend state on:

  * App launch
  * UI reload
  * Window focus regain

No implicit transitions allowed.

---

## Kill Switch Toggle Rules

* Toggle reflects backend state only
* Toggle action sends request, does not assume success
* If backend rejects change, UI must revert

---

## Tray & UI Consistency

* Tray actions may change backend state
* UI must update automatically in response
* UI must never require manual refresh

---

## Forbidden UI Behaviors

The following are violations:

* Showing "Connected" while `vpn_connected = false`
* Hiding recovery actions in Recovery Mode
* Allowing UI to disable Kill Switch silently
* UI state diverging from tray state

---

## Relationship to Other Contracts

This contract enforces:

* Protection Policy v1.0
* Backend Firewall Contract
* Tray Behavior Contract
* Recovery Policy

If conflicts arise, **Protection Policy v1.0 takes precedence**.

---

## Change Control

Any change to UI behavior requires:

* Update to this document
* Review against protection and recovery policies

---

End of UI State Contract
