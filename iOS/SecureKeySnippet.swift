import Foundation
import Security

class KeychainManager {
    // MARK: - Error Definition
    enum KeychainError: Error {
        case storeError(OSStatus)
        case retrieveError(OSStatus)
        case deleteError(OSStatus)
        case keyNotFound
        case unexpectedData
        case encodingError
    }

    // MARK: - Properties
    private let service: String
    private let accessGroup: String?

    // MARK: - Initialization
    init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    // MARK: - Public Methods
    func storeKey(_ key: String) throws {
        guard let data = key.data(using: .utf8) else {
            throw KeychainError.encodingError
        }

        // Prepare query
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "hmac_key",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Add access group if specified
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        // Delete existing key if any
        SecItemDelete(query as CFDictionary)

        // Add new key
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeError(status)
        }
    }

    func retrieveKey() throws -> String {
        // Prepare query
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "hmac_key",
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]

        // Add access group if specified
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        // Search keychain
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainError.retrieveError(status)
        }

        guard let data = result as? Data,
              let key = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }

        return key
    }

    func deleteKey() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "hmac_key"
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteError(status)
        }
    }
}

// MARK: - Enhanced Security Version
extension KeychainManager {
    func storeKeyWithBiometry(_ key: String) throws {
        guard let data = key.data(using: .utf8) else {
            throw KeychainError.encodingError
        }

        // Create access control
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryAny,
            &error
        ) else {
            throw error?.takeRetainedValue() ?? KeychainError.unexpectedData
        }

        // Prepare query with biometry
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "hmac_key",
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        // Delete existing key
        SecItemDelete(query as CFDictionary)

        // Store new key
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeError(status)
        }
    }
}