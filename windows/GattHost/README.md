<!-- Modified by Rui MA on 26 Sep 2026 -->

# GattHost

The foreground `unlock_gatt_host` is a transport for the installed LocalSystem
saved-credential service. It advertises four characteristics, forwards the
`0x01` request and signed assertion to that service, and notifies the iPhone
of the result. The service, not GATT, issues the challenge, verifies the
signature and controls the one-time credential grant. `unlock_approved` means
the grant is ready for a manual lock-screen tile claim; it does not mean that
Windows has unlocked. The old foreground `unlock_service_host` remains a
separate protocol diagnostic and must not be run as part of this path.

After a separately authorized build and Components Wizard installation, run
the prebuilt GATT host in the signed-in console session before locking:

```powershell
windows/build/unlock_gatt_host.exe
```

Install a saved MSA credential and enroll the iPhone public key for the same
console account SID before expecting a phone grant. Run `unlock_pairing_tool`
elevated on the unlocked console; it requires confirmation and asks the saved-
credential service to reload the record. The GATT enrollment command launches
the sibling pairing tool without elevation, so use the elevated tool directly
unless GATT host itself was deliberately started elevated. Pairing and password
storage are separate operations. An enrolled key on a different Windows
installation/SID is not transferable as an authorization for this account.

Run the authentication host as the signed-in console user without elevation.
On 2 Oct 2026, an unlocked elevated host reached the service and received
`not_ready`, while the unelevated host reported `service_unavailable`. The
installed service was Running as LocalSystem and matched the build's SHA-256.
The client had required reading the LocalSystem process token, an inappropriate
cross-account permission requirement for a normal desktop transport. The source
now verifies the named pipe server PID/session against SCM's running service
PID, LocalSystem configuration and exact configured System32 executable command.
The first correction still queried the LocalSystem process and the physical
retest returned `server-verification / win32=5`; that remaining cross-account
process-query requirement has now been removed. The specific failing API in
that retest was not captured. After rebuilding, an unelevated lock-screen run
reached the service and relayed an accepted signed assertion. Ordinary users
cannot register/reconfigure this service; the running own-process service PID
from SCM is the identity authority.
IPC failures now include `stage`, verification `check` and `win32` in the host log. `not_ready` while
the console is unlocked is expected; `service_unavailable` indicates IPC or
server-verification failure, before the service's challenge policy is applied.

On an existing locked session, keep the iPhone app in the foreground and tap
**Start connection**. The phone signs the service's 30-second challenge; an
accepted signature arms a 120-second, one-use credential grant. Manually select
the Credential Provider tile's saved-credential checkbox and submit without
typing the password. The LogonUI tile performs the native Negotiate packing;
GATT neither handles plaintext nor invokes a Windows logon API. Missing vault,
wrong enrolled SID, an unlocked console or a pending grant returns a failure
status instead of a challenge. A failed claim requires another phone challenge.

An earlier physical-machine lock-screen smoke test showed that the existing
foreground host remained reachable while Windows was locked: the iPhone got a
184-byte challenge, sent a 382-byte assertion, and the old verifier reported
`unlock_approved`. That earlier run proved transport feasibility only. On
2 Oct 2026, the rebuilt saved-credential bridge produced `unlock_approved` on
the phone; manual submission of the saved-credential tile then unlocked the
existing session without typing a password. This is a foreground, manually
submitted result on one physical Windows computer, not background or automatic
unlock acceptance. Native password entry remained usable.

The foreground host is not a background GATT service; package identity,
`bluetooth` capability and background lifecycle remain future work. Lock-screen
reachability must be tested on each intended configuration, not inferred from
the earlier physical-machine observation. The code has no VM-versus-physical
machine mode: the physical machine is used because its BLE hardware can exercise
the transport, while the previously completed VM tests establish the separate
saved-password and native-unlock behavior.

Request `0x02` plus a 65-byte P-256 public key still starts explicit enrollment
through the sibling pairing tool and Windows confirmation; it never writes an
enrollment key directly. Device name, advertisement and RSSI never authorize
the release of a saved credential.

Reference: [GattServiceProvider.CreateAsync and bluetooth capability](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovider.createasync).

References for server verification:

- [OpenProcessToken cross-account access requirements](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [SCM and service query access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [QueryServiceStatusEx running process ID](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [GetNamedPipeServerSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserversessionid)
