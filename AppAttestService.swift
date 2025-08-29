//
//  AppAttestService.swift
//  Roast Reel
//
//  Created by Darwin Miller on 6/21/25.
//

import Foundation
import DeviceCheck
import CryptoKit

// A service to handle App Attest logic.
@MainActor
class AppAttestService {

    static let shared = AppAttestService()
    private let keyIdStorageKey = "com.roastreel.appattest.keyid"
    private let networkService = NetworkService()
    private let service = DCAppAttestService.shared

    /// A boolean to quickly check if a session token exists.
    var hasSession: Bool {
        return KeychainService.loadToken() != nil
    }

    private init() {}

    /// The core App Attest flow. It will either get an existing key or create and attest a new one.
    func initializeAndValidate() async {
        // DCAppAttestService.isSupported is not a reliable check for jailbreaking
        // and all modern iOS devices support it. We can proceed directly.
                if let bundleId = Bundle.main.bundleIdentifier {
            print("Verifying App Attest with Bundle ID: \(bundleId)")
        }

        guard let keyId = getKeyId() else {
            print("No key found, generating a new one.")
            await generateAndAttestNewKey()
            return
        }

        print("Found existing App Attest key with ID: \(keyId)")
        // On subsequent launches, we assume the JWT in the keychain is still valid.
        // The NetworkService will automatically use it. If it's expired, our app
        // should have logic to prompt for re-authentication.
    }

    /// Generates a new key pair and sends the public key to your server for attestation by Apple.
    private func generateAndAttestNewKey() async {
        do {
            // Generate a new key pair. The private key is stored in the Secure Enclave.
            let keyId = try await DCAppAttestService.shared.generateKey()
            print("Generated new key with ID: \(keyId)")
            
            // 1. Fetch the challenge from your server.
            let challengeString = try await networkService.fetchChallenge()
            
            // 2. Hash the challenge for the attestation call.
            guard let challengeData = Data(base64Encoded: challengeString) else {
                throw AppAttestError.dataEncodingFailed
            }
            let hash = Data(SHA256.hash(data: challengeData))

            // 3. Request attestation from Apple.
            let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: hash)
            
            // 4. Send the attestation object to your server for verification and get a session token.
            let token = try await networkService.registerDevice(
                keyId: keyId,
                attestationObject: attestation.base64EncodedString(),
                challenge: challengeString
            )

            // 5. If the server successfully verifies the attestation, save the identifiers.
            try saveKeyId(keyId)
            KeychainService.save(token: token)
            print("Successfully attested and saved new keyId and session token.")

        } catch {
            print("App Attest key generation or attestation failed: \(error)")
            // Handle specific errors, e.g., if the server is unavailable, you might retry.
            // If other errors occur, you might need to inform the user or log the issue.
        }
    }
    
    /// Generates an assertion for a given request body to prove its authenticity.
    func generateAssertion(for requestData: Data) async throws -> Data {
        guard let keyId = getKeyId() else {
            // This case should ideally not happen if initialization is handled correctly.
            // You might want to trigger the key generation flow again.
            throw AppAttestError.keyNotFound
        }
        
        // For DCAppAttest, the server will verify signature over authenticatorData || clientDataHash
        // We pass clientDataHash computed here; authenticatorData is produced by the API.
        let hash = Data(SHA256.hash(data: requestData))
        
        // Log the hash for debugging purposes
        print("[AppAttestService] Generating assertion with clientDataHash: \(hash.base64EncodedString())")
        
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: hash)
        // Debug: log size to correlate with server
        print("Generated assertion bytes: \(assertion.count)")
        return assertion
    }

    // MARK: - Key Management (Using Keychain)

    private func saveKeyId(_ keyId: String) throws {
        // This keyId is not sensitive, but using Keychain is a convenient private store.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyIdStorageKey,
            kSecValueData as String: keyId.data(using: .utf8)!
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AppAttestError.keychainError(status)
        }
    }

    private func getKeyId() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyIdStorageKey,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: kCFBooleanTrue!
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            guard let data = dataTypeRef as? Data else { return nil }
            return String(data: data, encoding: .utf8)
        }
        return nil
    }

    /// Exposes the current App Attest key identifier for client flows (e.g., assertion-based refresh).
    /// This value is not sensitive but is needed by the server to associate the assertion with the device record.
    func currentKeyId() -> String? {
        return getKeyId()
    }

    /// Clears all App Attest and user data from the Keychain. This is useful for debugging.
    func clearKeychain() {
        print("Clearing keychain data for debug purposes...")
        // Delete the App Attest Key ID
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyIdStorageKey
        ]
        SecItemDelete(query as CFDictionary)
        
        // Delete the JWT
        KeychainService.deleteToken()
        
        print("Keychain data cleared.")
    }
}

enum AppAttestError: Error {
    case keyNotFound
    case serverVerificationFailed
    case keychainError(OSStatus)
    case dataEncodingFailed
    case networkError(Error)
} 
