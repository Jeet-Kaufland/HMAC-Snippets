import Foundation
import CommonCrypto
import CryptoKit

class DataEncryption {
    // MARK: - Types
    enum EncryptionError: Error {
        case invalidKey
        case encryptionFailed
        case decryptionFailed
        case invalidTimestamp
        case invalidEndpoint
    }

    struct EncryptedData {
        let encryptedValue: String
        let iv: String
    }

    // MARK: - Constants
    private let ivSize = kCCBlockSizeAES128
    private let keySize = kCCKeySizeAES256

    // MARK: - Public Methods
    func encryptTimestamp(_ timestamp: String, secretKey: String) throws -> EncryptedData {
        // Validate timestamp
        guard let _ = TimeInterval(timestamp) else {
            throw EncryptionError.invalidTimestamp
        }

        return try encryptWithAES(timestamp, secretKey: secretKey)
    }

    func encryptEndpoint(_ endpointUrl: String, secretKey: String) throws -> EncryptedData {
        // Validate endpoint
        guard endpointUrl.starts(with: "/") else {
            throw EncryptionError.invalidEndpoint
        }

        return try encryptWithAES(endpointUrl, secretKey: secretKey)
    }

    func decryptData(_ encryptedData: EncryptedData, secretKey: String) throws -> String {
        guard let keyData = secretKey.data(using: .utf8) else {
            throw EncryptionError.invalidKey
        }

        guard let ivData = Data(base64Encoded: encryptedData.iv),
              let encryptedData = Data(base64Encoded: encryptedData.encryptedValue) else {
            throw EncryptionError.decryptionFailed
        }

        let key = try deriveKey(fromPassword: keyData)

        guard let decryptedData = try? decrypt(
            data: encryptedData,
            key: key,
            iv: ivData
        ) else {
            throw EncryptionError.decryptionFailed
        }

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EncryptionError.decryptionFailed
        }

        return decryptedString
    }

    // MARK: - Private Methods
    private func encryptWithAES(_ data: String, secretKey: String) throws -> EncryptedData {
        guard let keyData = secretKey.data(using: .utf8) else {
            throw EncryptionError.invalidKey
        }

        guard let dataToEncrypt = data.data(using: .utf8) else {
            throw EncryptionError.encryptionFailed
        }

        // Generate random IV
        let iv = generateIV()

        // Derive key
        let key = try deriveKey(fromPassword: keyData)

        // Encrypt
        let encryptedData = try encrypt(
            data: dataToEncrypt,
            key: key,
            iv: iv
        )

        return EncryptedData(
            encryptedValue: encryptedData.base64EncodedString(),
            iv: iv.base64EncodedString()
        )
    }

    private func generateIV() -> Data {
        var iv = Data(count: ivSize)
        _ = iv.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, ivSize, bytes.baseAddress!)
        }
        return iv
    }

    private func deriveKey(fromPassword password: Data) throws -> SymmetricKey {
        let salt = "YourAppSalt".data(using: .utf8)! // In production, use a proper salt
        let rounds = 100000

        let derivedKeyData = try password.withUnsafeBytes { passwordBytes -> Data in
            var derivedKey = Data(count: keySize)

            let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    password.count,
                    salt.withUnsafeBytes { saltBytes in
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    },
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(rounds),
                    derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    keySize
                )
            }

            guard result == kCCSuccess else {
                throw EncryptionError.encryptionFailed
            }

            return derivedKey
        }

        return SymmetricKey(data: derivedKeyData)
    }

    private func encrypt(data: Data, key: SymmetricKey, iv: Data) throws -> Data {
        let sealedBox = try AES.GCM.seal(
            data,
            using: key,
            nonce: try AES.GCM.Nonce(data: iv)
        )

        return sealedBox.ciphertext
    }
}

// MARK: - Request Data
struct RequestData {
    let timestamp: String
    let endpoint: String
    let timestampIv: String
    let endpointIv: String
}

// MARK: - Encryption Manager
class EncryptionManager {
    private let keystoreManager: KeystoreManager
    private let dataEncryption: DataEncryption

    init(keystoreManager: KeystoreManager, dataEncryption: DataEncryption) {
        self.keystoreManager = keystoreManager
        self.dataEncryption = dataEncryption
    }

    func prepareRequestData(endpointUrl: String) throws -> RequestData {
        let secretKey = try keystoreManager.retrieveKey()
        let currentTimestamp = String(Int(Date().timeIntervalSince1970 * 1000))

        let encryptedTimestamp = try dataEncryption.encryptTimestamp(
            currentTimestamp,
            secretKey: secretKey
        )

        let encryptedEndpoint = try dataEncryption.encryptEndpoint(
            endpointUrl,
            secretKey: secretKey
        )

        return RequestData(
            timestamp: encryptedTimestamp.encryptedValue,
            endpoint: encryptedEndpoint.encryptedValue,
            timestampIv: encryptedTimestamp.iv,
            endpointIv: encryptedEndpoint.iv
        )
    }
}

// MARK: - API Client
class APIClient {
    private let encryptionManager: EncryptionManager
    private let session: URLSession

    init(encryptionManager: EncryptionManager, session: URLSession = .shared) {
        self.encryptionManager = encryptionManager
        self.session = session
    }

    func makeAPICall(endpointUrl: String) async throws {
        let requestData = try encryptionManager.prepareRequestData(endpointUrl: endpointUrl)

        var request = URLRequest(url: URL(string: "https://api.yourserver.com\(endpointUrl)")!)
        request.addValue(requestData.timestamp, forHTTPHeaderField: "X-Encrypted-Timestamp")
        request.addValue(requestData.timestampIv, forHTTPHeaderField: "X-Timestamp-IV")
        request.addValue(requestData.endpoint, forHTTPHeaderField: "X-Encrypted-Endpoint")
        request.addValue(requestData.endpointIv, forHTTPHeaderField: "X-Endpoint-IV")

        let (data, response) = try await session.data(for: request)
        // Handle response...
    }
}

// MARK: - Usage Example
class ExampleViewController: UIViewController {
    private let apiClient: APIClient

    init(apiClient: APIClient) {
        self.apiClient = apiClient
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func makeCall() async {
        do {
            try await apiClient.makeAPICall(endpointUrl: "/api/data")
        } catch {
            handleError(error)
        }
    }

    private func handleError(_ error: Error) {
        let message: String

        switch error {
        case DataEncryption.EncryptionError.invalidKey:
            message = "Invalid encryption key"
        case DataEncryption.EncryptionError.encryptionFailed:
            message = "Encryption failed"
        case DataEncryption.EncryptionError.invalidTimestamp:
            message = "Invalid timestamp"
        case DataEncryption.EncryptionError.invalidEndpoint:
            message = "Invalid endpoint"
        default:
            message = "An error occurred"
        }

        // Show error to user
        let alert = UIAlertController(
            title: "Error",
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}