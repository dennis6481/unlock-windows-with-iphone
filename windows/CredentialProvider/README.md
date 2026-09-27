<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider prototype

This directory contains a build-only `CPUS_UNLOCK_WORKSTATION` Credential
Provider shell. It exposes one read-only “Unlock Windows with iPhone” tile so
the COM contract can be tested against the installed Windows SDK.

The serialization adapter can pack an already-approved challenge, key ID,
raw SID and raw `r || s` signature into the shared `UnlockLogonBuffer` and the
Windows `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` shape. It does not
verify the signature, fetch a password, or accept data from an environment
variable. A future protected IPC client will supply the approval; the LSA
Authentication Package must verify it independently.

The current prototype deliberately does not:

- register a Credential Provider CLSID;
- submit a password, PIN, software key or Windows logon token;
- trust an `unlock_approved` result as a login token;
- load or register an LSA Authentication Package;
- claim that selecting the tile unlocks Windows.

The COM tile's `GetSerialization` still returns `CPGSR_NO_CREDENTIAL_FINISHED`
with a warning until the LSA package and a protected, short-lived approval
handoff are implemented. `CredentialProviderTests` loads the DLL directly,
instantiates it through `DllGetClassObject`, verifies the unlock-workstation
tile and confirms that no credential serialization is returned. The same test
also validates the separate serialization adapter against the shared codec;
it is not a bypass around the protected handoff.
