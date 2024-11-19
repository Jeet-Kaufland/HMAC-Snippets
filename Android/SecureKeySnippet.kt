import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreManager {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "HMACKeyAlias"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }

    // Store your HMAC key securely
    fun encryptAndStoreKey(hmacKey: String): String {
        // Get or generate key from Android Keystore
        val secretKey = getOrCreateSecretKey()

        // Encrypt the HMAC key
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        // Perform encryption
        val encrypted = cipher.doFinal(hmacKey.toByteArray(Charsets.UTF_8))

        // Combine IV with encrypted data (we need IV for decryption)
        val combined = cipher.iv + encrypted

        // Return as Base64 string for easy storage
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    // Retrieve and decrypt your HMAC key
    fun retrieveKey(encryptedKey: String): String {
        // Get the existing key from Keystore
        val secretKey = getOrCreateSecretKey()

        // Decode from Base64
        val combined = Base64.decode(encryptedKey, Base64.DEFAULT)

        // Extract IV and encrypted data
        val iv = combined.slice(0..11).toByteArray()  // GCM IV is 12 bytes
        val encrypted = combined.slice(12..combined.lastIndex).toByteArray()

        // Initialize cipher for decryption
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        // Decrypt and convert back to string
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private fun getOrCreateSecretKey(): SecretKey {
        // Try to get existing key
        keyStore.getKey(KEY_ALIAS, null)?.let { return it as SecretKey }

        // If key doesn't exist, generate a new one
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // Require user authentication for accessing the key
            .setUserAuthenticationRequired(false) // Set to true if you want biometric auth
            // Key is invalidated if user adds new biometric enrollment
            .setInvalidatedByBiometricEnrollment(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }
}

// Usage example
class MainActivity : AppCompatActivity() {
    private lateinit var keystoreManager: KeystoreManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        keystoreManager = KeystoreManager()

        try {
            // Store the HMAC key
            val hmacKey = "HelloKey"
            val encryptedKey = keystoreManager.encryptAndStoreKey(hmacKey)

            // Save the encrypted key to SharedPreferences or other storage
            getSharedPreferences("keys", Context.MODE_PRIVATE)
                .edit()
                .putString("encrypted_hmac_key", encryptedKey)
                .apply()

            // Later, when you need the key:
            val storedEncryptedKey = getSharedPreferences("keys", Context.MODE_PRIVATE)
                .getString("encrypted_hmac_key", null)

            storedEncryptedKey?.let {
                val decryptedKey = keystoreManager.retrieveKey(it)
                // Use decryptedKey for HMAC operations
                println("Retrieved key: $decryptedKey")
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}