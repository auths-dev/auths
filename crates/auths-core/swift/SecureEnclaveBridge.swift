// SecureEnclaveBridge.swift — Thin C-ABI bridge to CryptoKit Secure Enclave.
//
// Exposes four functions via @_cdecl for Rust FFI:
//   se_is_available()  — check SE hardware
//   se_create_key()    — generate P-256 key in SE, return handle + compressed pubkey
//   se_sign()          — restore key from handle, sign with biometric, return r||s
//   se_load_key()      — restore key from handle, return compressed pubkey
//
// Error codes: 0=success, 1=not_available, 2=auth_failed, 3=key_error

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Availability

@_cdecl("se_is_available")
public func seIsAvailable() -> Bool {
    return SecureEnclave.isAvailable
}

// MARK: - Create Key

/// Create a P-256 key in the Secure Enclave.
///
/// Returns the key's opaque `dataRepresentation` (for persistence) and
/// the 33-byte compressed SEC1 public key.
///
/// - Parameters:
///   - outHandle: buffer for dataRepresentation (caller provides, >= 256 bytes)
///   - outHandleLen: on return, actual handle length
///   - outPubkey: buffer for compressed public key (caller provides, >= 33 bytes)
///   - outPubkeyLen: on return, actual pubkey length (33)
/// - Returns: 0 on success, error code on failure
@_cdecl("se_create_key")
public func seCreateKey(
    _ outHandle: UnsafeMutablePointer<UInt8>,
    _ outHandleLen: UnsafeMutablePointer<Int>,
    _ outPubkey: UnsafeMutablePointer<UInt8>,
    _ outPubkeyLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return 1 }

    do {
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            nil
        )!

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: accessControl
        )

        // Export opaque handle (encrypted blob, only this SE can use)
        let handleData = privateKey.dataRepresentation
        handleData.copyBytes(to: outHandle, count: handleData.count)
        outHandleLen.pointee = handleData.count

        // Export compressed public key (33 bytes)
        let compressedPub = privateKey.publicKey.compressedRepresentation
        compressedPub.copyBytes(to: outPubkey, count: compressedPub.count)
        outPubkeyLen.pointee = compressedPub.count

        return 0
    } catch {
        return 3
    }
}

// MARK: - Sign

/// Restore a key from its handle and sign data. Triggers biometric prompt.
///
/// - Parameters:
///   - handle: the dataRepresentation blob from se_create_key
///   - handleLen: length of handle
///   - msg: message bytes to sign
///   - msgLen: message length
///   - outSig: buffer for signature (caller provides, >= 64 bytes)
///   - outSigLen: on return, actual signature length (64)
/// - Returns: 0 on success, 1=not_available, 2=auth_failed, 3=key_error
@_cdecl("se_sign")
public func seSign(
    _ handle: UnsafePointer<UInt8>, _ handleLen: Int,
    _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
    _ outSig: UnsafeMutablePointer<UInt8>,
    _ outSigLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return 1 }

    do {
        let handleData = Data(bytes: handle, count: handleLen)
        let context = LAContext()
        context.localizedReason = "Sign with auths"

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: handleData,
            authenticationContext: context
        )

        let msgData = Data(bytes: msg, count: msgLen)
        let signature = try privateKey.signature(for: msgData)

        // rawRepresentation is exactly 64 bytes: r (32) || s (32)
        let rawSig = signature.rawRepresentation
        rawSig.copyBytes(to: outSig, count: rawSig.count)
        outSigLen.pointee = rawSig.count

        return 0
    } catch let error as LAError where error.code == .userCancel || error.code == .authenticationFailed {
        return 2
    } catch {
        return 3
    }
}

// MARK: - Load Key (get public key from handle)

/// Restore a key from its handle and return the compressed public key.
/// Does NOT trigger biometric (public key access doesn't require auth).
///
/// - Parameters:
///   - handle: the dataRepresentation blob
///   - handleLen: length of handle
///   - outPubkey: buffer for compressed public key (>= 33 bytes)
///   - outPubkeyLen: on return, actual pubkey length (33)
/// - Returns: 0 on success, error code on failure
@_cdecl("se_load_key")
public func seLoadKey(
    _ handle: UnsafePointer<UInt8>, _ handleLen: Int,
    _ outPubkey: UnsafeMutablePointer<UInt8>,
    _ outPubkeyLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return 1 }

    do {
        let handleData = Data(bytes: handle, count: handleLen)
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: handleData
        )

        let compressedPub = privateKey.publicKey.compressedRepresentation
        compressedPub.copyBytes(to: outPubkey, count: compressedPub.count)
        outPubkeyLen.pointee = compressedPub.count

        return 0
    } catch {
        return 3
    }
}
