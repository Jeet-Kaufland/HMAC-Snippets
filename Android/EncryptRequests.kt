import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import java.security.SecureRandom
import java.net.URL

class DataEncryption {
    companion object {
        private const val ALGORITHM = "AES/CBC/PKCS7Padding"
        private const val IV_LENGTH = 16
    }

    data class EncryptedData(
        val encryptedValue: String,
        val iv: String
    )

    sealed class EncryptionError : Exception() {
        object InvalidKeyError : EncryptionError()
        object EncryptionError : EncryptionError()
        object DecryptionError : EncryptionError()
        object InvalidTimestampError : EncryptionError()
        object InvalidEndpointError : EncryptionError()
    }

    // Timestamp specific encryption
    fun encryptTimestamp(timestamp: String, secretKey: String): EncryptedData {
        // Validate timestamp
        try {
            timestamp.toLong()
        } catch (e: NumberFormatException) {
            throw EncryptionError.InvalidTimestampError
        }
        
        return encryptWithAES(timestamp, secretKey)
    }

    // Endpoint specific encryption
    fun encryptEndpoint(endpointUrl: String, secretKey: String): EncryptedData {
        // Validate endpoint
        try {
            require(endpointUrl.startsWith("/")) { "Endpoint must start with /" }
            // Additional URL validation if needed
        } catch (e: Exception) {
            throw EncryptionError.InvalidEndpointError
        }
        
        return encryptWithAES(endpointUrl, secretKey)
    }

    private fun encryptWithAES(data: String, secretKey: String): EncryptedData {
        try {
            // Generate random IV
            val iv = ByteArray(IV_LENGTH).apply {
                SecureRandom().nextBytes(this)
            }

            // Create key specification
            val keySpec = SecretKeySpec(
                secretKey.toByteArray(Charsets.UTF_8).copyOf(32),
                "AES"
            )

            // Initialize cipher
            val cipher = Cipher.getInstance(ALGORITHM)
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

            // Encrypt
            val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

            return EncryptedData(
                encryptedValue = Base64.encodeToString(encrypted, Base64.NO_WRAP),
                iv = Base64.encodeToString(iv, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            throw EncryptionError.EncryptionError
        }
    }
}

data class RequestData(
    val timestamp: String,
    val endpoint: String,
    val timestampIv: String,
    val endpointIv: String
)

class EncryptionManager(
    private val keystoreManager: KeystoreManager,
    private val dataEncryption: DataEncryption
) {
    fun prepareRequestData(endpointUrl: String): RequestData {
        try {
            val secretKey = keystoreManager.retrieveKey()
            val currentTimestamp = System.currentTimeMillis().toString()
            
            val encryptedTimestamp = dataEncryption.encryptTimestamp(
                currentTimestamp,
                secretKey
            )
            
            val encryptedEndpoint = dataEncryption.encryptEndpoint(
                endpointUrl,
                secretKey
            )
            
            return RequestData(
                timestamp = encryptedTimestamp.encryptedValue,
                endpoint = encryptedEndpoint.encryptedValue,
                timestampIv = encryptedTimestamp.iv,
                endpointIv = encryptedEndpoint.iv
            )
        } catch (e: Exception) {
            // Log error securely (without sensitive data)
            throw e
        }
    }
}

// Hyptothetical API Client (HTTP Interceptor in our case)
class ApiClient(private val encryptionManager: EncryptionManager) {
    fun makeApiCall(endpointUrl: String) {
        try {
            val requestData = encryptionManager.prepareRequestData(endpointUrl)
            
            val request = Request.Builder()
                .url("https://api.yourserver.com${endpointUrl}")
                .addHeader("X-Encrypted-Timestamp", requestData.timestamp)
                .addHeader("X-Timestamp-IV", requestData.timestampIv)
                .addHeader("X-Encrypted-Endpoint", requestData.endpoint)
                .addHeader("X-Endpoint-IV", requestData.endpointIv)
                .build()
            
            // Execute request...
            
        } catch (e: Exception) {
            when (e) {
                is DataEncryption.EncryptionError -> handleEncryptionError(e)
                else -> handleGenericError(e)
            }
        }
    }
}