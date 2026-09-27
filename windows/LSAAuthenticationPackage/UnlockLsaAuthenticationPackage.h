// Created by Rui MA on 27 Sep 2026

#pragma once

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <ntsecapi.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <sspi.h>
#include <NTSecPKG.h>

extern "C" {

__declspec(dllexport) NTSTATUS NTAPI LsaApInitializePackage(
    ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING Database,
    PLSA_STRING Confidentiality,
    PLSA_STRING* AuthenticationPackageName
);

__declspec(dllexport) NTSTATUS NTAPI LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    PVOID* ProfileBuffer,
    PULONG ProfileBufferSize,
    PLUID LogonId,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID* TokenInformation,
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority,
    PUNICODE_STRING* MachineName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* SupplementalCredentials
);

__declspec(dllexport) NTSTATUS NTAPI LsaApCallPackage(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID* ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
);

__declspec(dllexport) NTSTATUS NTAPI LsaApCallPackageUntrusted(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID* ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
);

__declspec(dllexport) NTSTATUS NTAPI LsaApCallPackagePassthrough(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID* ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
);

__declspec(dllexport) VOID NTAPI LsaApLogonTerminated(PLUID LogonId);

} // extern "C"
