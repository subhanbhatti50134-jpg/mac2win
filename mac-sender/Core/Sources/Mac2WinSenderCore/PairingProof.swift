import CryptoKit
import Foundation

/// PIN-bound pairing proof (protocol/PROTOCOL.md §2.3, ADR-003).
/// HKDF-SHA256(PIN, salt=certFingerprintHex, info="mac2win-pair-v1") then
/// HMAC-SHA256 over clientNonce|serverNonce|devicePublicKey (base64, '|'-joined).
/// Standard CryptoKit primitives only — no custom cryptography.
public enum PairingProof {
    public static let hkdfInfo = Data("mac2win-pair-v1".utf8)

    public static func derivePinKey(pin: String, certFingerprintHex: String) -> SymmetricKey {
        precondition(!pin.isEmpty, "PIN must not be empty")
        precondition(!certFingerprintHex.isEmpty, "fingerprint must not be empty")
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(pin.utf8)),
            salt: Data(certFingerprintHex.lowercased().utf8),
            info: hkdfInfo,
            outputByteCount: 32)
    }

    /// Message bytes: UTF8(clientNonceB64) || '|' || UTF8(serverNonceB64) || '|' || UTF8(devicePublicKeyB64)
    public static func buildMessage(
        clientNonceB64: String, serverNonceB64: String, devicePublicKeyB64: String
    ) -> Data {
        Data("\(clientNonceB64)|\(serverNonceB64)|\(devicePublicKeyB64)".utf8)
    }

    public static func computeProof(
        pin: String, certFingerprintHex: String,
        clientNonceB64: String, serverNonceB64: String, devicePublicKeyB64: String
    ) -> Data {
        let key = derivePinKey(pin: pin, certFingerprintHex: certFingerprintHex)
        let message = buildMessage(
            clientNonceB64: clientNonceB64, serverNonceB64: serverNonceB64,
            devicePublicKeyB64: devicePublicKeyB64)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    /// Constant-time verification (CryptoKit's isValidAuthenticationCode is timing-safe).
    public static func verify(
        pin: String, certFingerprintHex: String,
        clientNonceB64: String, serverNonceB64: String, devicePublicKeyB64: String,
        presentedProof: Data
    ) -> Bool {
        let key = derivePinKey(pin: pin, certFingerprintHex: certFingerprintHex)
        let message = buildMessage(
            clientNonceB64: clientNonceB64, serverNonceB64: serverNonceB64,
            devicePublicKeyB64: devicePublicKeyB64)
        return HMAC<SHA256>.isValidAuthenticationCode(presentedProof, for: message, using: key)
    }

    public static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
