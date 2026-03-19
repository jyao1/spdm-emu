# SPDM Authorization (DSP0289) Validation Guide

This document describes how to validate the USAP (User-Space Authorization Protocol) and SEAP (Secure Enclave Authorization Protocol) authorization session flows using `spdm_requester_emu` and `spdm_responder_emu`.

## Overview

The `--exe_session AUTH` flag activates the DSP0289 authorization session in a KEY_EXCHANGE session.
The `--auth_role` flag selects the local authorization role.

The MCTP or PCI_DOE transport must be used (TCP is not supported for AUTH sessions).

The auth session covers the following flow (both USAP and SEAP):

1. GET_AUTH_VERSION / AUTH_VERSION
2. SELECT_AUTH_VERSION / SELECT_AUTH_VERSION_RSP
3. GET_AUTH_CAPABILITIES / AUTH_CAPABILITIES
4. (USAP) START_AUTH / START_AUTH_RSP — opens a USAS
   (SEAP) ELEVATE_PRIVILEGE / PRIVILEGE_ELEVATED — elevates session privilege
5. Authenticated operations: GET_CRED_ID_PARAMS, SET_CRED_ID_PARAMS, GET_AUTH_POLICY, SET_AUTH_POLICY, TAKE_OWNERSHIP, AUTH_RESET_TO_DEFAULT
6. (USAP) END_AUTH / END_AUTH_RSP — closes or persists the USAS
   (SEAP) END_ELEVATED_PRIVILEGE / ELEVATED_PRIVILEGE_ENDED

## Prerequisites

Build the emulator as described in the [README](../README.md):

```bash
# Linux/macOS
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=mbedtls ..
make

# Windows (Developer Command Prompt for VS 2022)
cmake -DARCH=x64 -DTOOLCHAIN=VS2022 -DTARGET=Debug -DCRYPTO=mbedtls -G"NMake Makefiles" ..
nmake
```

Copy sample keys before running:

```bash
# Linux/macOS
cp ../../libspdm/build/bin/spdm_auth_device_secret_lib_sample.so .    # if applicable
# Actually run copy_sample_key script as described in README.md
```

All commands below are run from the `build/bin` directory.

---

## USAP (User-Space Authorization Protocol)

USAP is used when the requester acts as the USAP Initiator and the responder acts as the USAP Target.

### Basic USAP validation

Open two terminals in `build/bin`.

**Terminal 1 — Responder (USAP Target):**

```bash
./spdm_responder_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role USAP_TARGET
```

**Terminal 2 — Requester (USAP Initiator):**

```bash
./spdm_requester_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role USAP_INIT
```

Expected requester output (key status lines):

```
auth_session_type - 1
auth_version count - 1
auth_version - 1000
select_auth_version - 10
auth_capabilities - done
start_auth - done
cred_id_params - done
set_cred_id_params - done
auth_policy - done
set_auth_policy - done
take_ownership - done
auth_reset_to_default - done
start_auth - done
auth_reset_to_default - done
start_auth - done
end_auth (persist) - done, saved_seq_num - 1
start_auth (continue) - done
cred_id_params (after continue) - done
end_auth - done
```

`auth_session_type - 1` indicates USAP (`LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP = 1`).

### USAP continuation

The test automatically exercises continuation (DSP0289 sec. 10.5.2):

1. `end_auth` with `PERSIST_METHOD_UNTIL_RESET` — saves the USAS and returns the `saved_sequence_number`.
2. `start_auth` with `is_continue=true` and the saved sequence number — resumes the persisted USAS.
3. An authenticated `get_cred_id_params` confirms the resumed USAS is functional.
4. `end_auth` with `PERSIST_METHOD_ERASE` — destroys the saved USAS cleanly.

The `saved_seq_num` printed is the sequence number at which the USAS was persisted, and the resumed USAS continues from that point.

### PCI_DOE transport (alternative)

```bash
# Responder
./spdm_responder_emu --trans PCI_DOE --exe_session KEY_EX,AUTH --auth_role USAP_TARGET

# Requester
./spdm_requester_emu --trans PCI_DOE --exe_session KEY_EX,AUTH --auth_role USAP_INIT
```

---

## SEAP (Secure Enclave Authorization Protocol)

SEAP is used when the requester acts as the SEAP Initiator and the responder acts as the SEAP Target. Instead of START_AUTH/END_AUTH, the session uses ELEVATE_PRIVILEGE/END_ELEVATED_PRIVILEGE.

### Basic SEAP validation

**Terminal 1 — Responder (SEAP Target):**

```bash
./spdm_responder_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role SEAP_TARGET
```

**Terminal 2 — Requester (SEAP Initiator):**

```bash
./spdm_requester_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role SEAP_INIT
```

Expected requester output (key status lines):

```
auth_session_type - 2
auth_version count - 1
auth_version - 1000
select_auth_version - 10
auth_capabilities - done
elevate_privilege - done
cred_id_params - done
set_cred_id_params - done
auth_policy - done
set_auth_policy - done
take_ownership - done
auth_reset_to_default - done
elevate_privilege - done
auth_reset_to_default - done
elevate_privilege - done
end_elevated_privilege - done
```

`auth_session_type - 2` indicates SEAP (`LIBSPDM_AUTH_SESSION_PROCESS_TYPE_SEAP = 2`).

After each `auth_reset_to_default`, the privilege level is terminated; the test re-enters elevated privilege with `elevate_privilege` before the next operation.

---

## Capturing traces

Use `--pcap` to capture a PCAP trace for offline analysis with [spdm-dump](https://github.com/DMTF/spdm-dump):

```bash
# USAP
./spdm_responder_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role USAP_TARGET \
    --pcap SpdmResponder.pcap > SpdmResponder.log

./spdm_requester_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role USAP_INIT \
    --pcap SpdmRequester.pcap > SpdmRequester.log

# SEAP
./spdm_responder_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role SEAP_TARGET \
    --pcap SpdmResponder.pcap > SpdmResponder.log

./spdm_requester_emu --trans MCTP --exe_session KEY_EX,AUTH --auth_role SEAP_INIT \
    --pcap SpdmRequester.pcap > SpdmRequester.log
```

---

## auth_role summary

| `--auth_role` value | Role                  | Side      | Session type value |
|---------------------|-----------------------|-----------|--------------------|
| `USAP_INIT`         | USAP Initiator        | Requester | 1 (USAP)           |
| `USAP_TARGET`       | USAP Target           | Responder | 1 (USAP)           |
| `SEAP_INIT`         | SEAP Initiator        | Requester | 2 (SEAP)           |
| `SEAP_TARGET`       | SEAP Target           | Responder | 2 (SEAP)           |

By default (no `--auth_role`), all roles are supported and the session type is determined by peer negotiation via AODS opaque data.
