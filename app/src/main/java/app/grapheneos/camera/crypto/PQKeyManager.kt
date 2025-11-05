package app.grapheneos.camera.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Key manager for ML-KEM public/private keys used in photo encryption.
 *
 * - Public key is stored in encrypted shared preferences for encrypting photos
 * - Private key is exported to a file for use with the desktop decryption utility
 * - Keys are encoded as Base64 for storage/export
 */
class PQKeyManager(private val context: Context) {
    companion object {
        private const val TAG = "PQKeyManager"
        private const val PREFS_NAME = "pqc_keys_prefs"
        private const val KEY_PUBLIC_KEY = "mlkem_public_key"
        private const val KEY_HAS_KEYPAIR = "has_keypair"
        private const val KEY_PENDING_PRIVATE_KEY = "pending_private_key_export"
        private const val KEY_PENDING_TIMESTAMP = "pending_private_key_timestamp"

        // PEM-like format markers for easy identification
        private const val PUBLIC_KEY_HEADER = "-----BEGIN MLKEM768 PUBLIC KEY-----"
        private const val PUBLIC_KEY_FOOTER = "-----END MLKEM768 PUBLIC KEY-----"
        private const val PRIVATE_KEY_HEADER = "-----BEGIN MLKEM768 PRIVATE KEY-----"
        private const val PRIVATE_KEY_FOOTER = "-----END MLKEM768 PRIVATE KEY-----"

        // Maximum time to keep pending private key (24 hours)
        private const val PENDING_KEY_MAX_AGE_MS = 24 * 60 * 60 * 1000L
    }

    private val prefs: SharedPreferences by lazy {
        try {
            // Use EncryptedSharedPreferences for secure storage
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create EncryptedSharedPreferences, falling back to regular prefs", e)
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    /**
     * Generate a new ML-KEM-768 keypair and store the public key.
     *
     * @return Pair of (public key file content, private key file content) for export
     */
    fun generateAndStoreKeyPair(): Pair<String, String> {
        val keyPair = PQCryptoManager.generateKeyPair()
        val publicKey = keyPair.public as MLKEMPublicKeyParameters
        val privateKey = keyPair.private as MLKEMPrivateKeyParameters

        // Store public key in encrypted preferences
        storePublicKey(publicKey)

        // Create exportable key files
        val publicKeyPem = encodePublicKeyToPem(publicKey)
        val privateKeyPem = encodePrivateKeyToPem(privateKey)

        Log.d(TAG, "Generated and stored new ML-KEM-768 keypair")

        return Pair(publicKeyPem, privateKeyPem)
    }

    /**
     * Store the public key in encrypted preferences.
     */
    fun storePublicKey(publicKey: MLKEMPublicKeyParameters) {
        val encoded = publicKey.encoded
        val base64 = Base64.encodeToString(encoded, Base64.NO_WRAP)

        prefs.edit()
            .putString(KEY_PUBLIC_KEY, base64)
            .putBoolean(KEY_HAS_KEYPAIR, true)
            .apply()

        Log.d(TAG, "Stored public key (${encoded.size} bytes)")
    }

    /**
     * Import a public key from PEM format string.
     *
     * @param pemString The PEM-formatted public key
     * @return true if import successful
     */
    fun importPublicKey(pemString: String): Boolean {
        return try {
            val publicKey = decodePublicKeyFromPem(pemString)
            storePublicKey(publicKey)
            Log.d(TAG, "Successfully imported public key")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to import public key", e)
            false
        }
    }

    /**
     * Get the stored public key for encryption.
     *
     * @return MLKEMPublicKeyParameters or null if not available
     */
    fun getPublicKey(): MLKEMPublicKeyParameters? {
        return try {
            val base64 = prefs.getString(KEY_PUBLIC_KEY, null) ?: return null
            val encoded = Base64.decode(base64, Base64.NO_WRAP)
            MLKEMPublicKeyParameters(PQCryptoManager.MLKEM_PARAMETERS, encoded)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load public key", e)
            null
        }
    }

    /**
     * Check if encryption is available (public key is stored).
     */
    fun isEncryptionAvailable(): Boolean {
        return prefs.getBoolean(KEY_HAS_KEYPAIR, false) && getPublicKey() != null
    }

    /**
     * Clear stored keys.
     */
    fun clearKeys() {
        prefs.edit().clear().apply()
        Log.d(TAG, "Cleared all stored keys")
    }

    /**
     * Export public key to PEM format for sharing.
     */
    private fun encodePublicKeyToPem(publicKey: MLKEMPublicKeyParameters): String {
        val encoded = publicKey.encoded
        val base64 = Base64.encodeToString(encoded, Base64.DEFAULT) // Use default for line breaks

        return buildString {
            appendLine(PUBLIC_KEY_HEADER)
            appendLine(base64.trim())
            append(PUBLIC_KEY_FOOTER)
        }
    }

    /**
     * Export private key to PEM format for desktop decryption utility.
     */
    private fun encodePrivateKeyToPem(privateKey: MLKEMPrivateKeyParameters): String {
        val encoded = privateKey.encoded
        val base64 = Base64.encodeToString(encoded, Base64.DEFAULT)

        return buildString {
            appendLine(PRIVATE_KEY_HEADER)
            appendLine(base64.trim())
            append(PRIVATE_KEY_FOOTER)
        }
    }

    /**
     * Decode public key from PEM format.
     */
    private fun decodePublicKeyFromPem(pemString: String): MLKEMPublicKeyParameters {
        val cleaned = pemString
            .replace(PUBLIC_KEY_HEADER, "")
            .replace(PUBLIC_KEY_FOOTER, "")
            .replace("\\s".toRegex(), "")

        val encoded = Base64.decode(cleaned, Base64.DEFAULT)
        return MLKEMPublicKeyParameters(PQCryptoManager.MLKEM_PARAMETERS, encoded)
    }

    /**
     * Decode private key from PEM format (for testing/utility).
     */
    fun decodePrivateKeyFromPem(pemString: String): MLKEMPrivateKeyParameters {
        val cleaned = pemString
            .replace(PRIVATE_KEY_HEADER, "")
            .replace(PRIVATE_KEY_FOOTER, "")
            .replace("\\s".toRegex(), "")

        val encoded = Base64.decode(cleaned, Base64.DEFAULT)
        return MLKEMPrivateKeyParameters(PQCryptoManager.MLKEM_PARAMETERS, encoded)
    }

    /**
     * Export private key to Downloads folder.
     *
     * @param privateKeyPem The PEM-formatted private key
     * @return File path where key was saved, or null on failure
     */
    fun exportPrivateKeyToFile(privateKeyPem: String): String? {
        return try {
            val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS
            )

            val timestamp = System.currentTimeMillis()
            val fileName = "camera_mlkem_private_key_$timestamp.pem"
            val file = File(downloadsDir, fileName)

            file.writeText(privateKeyPem)

            Log.d(TAG, "Exported private key to: ${file.absolutePath}")
            file.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export private key", e)
            null
        }
    }

    /**
     * Export public key to Downloads folder.
     *
     * @param publicKeyPem The PEM-formatted public key
     * @return File path where key was saved, or null on failure
     */
    fun exportPublicKeyToFile(publicKeyPem: String): String? {
        return try {
            val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS
            )

            val timestamp = System.currentTimeMillis()
            val fileName = "camera_mlkem_public_key_$timestamp.pem"
            val file = File(downloadsDir, fileName)

            file.writeText(publicKeyPem)

            Log.d(TAG, "Exported public key to: ${file.absolutePath}")
            file.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export public key", e)
            null
        }
    }

    /**
     * Store pending private key temporarily in encrypted preferences.
     * This prevents loss due to configuration changes or process death.
     *
     * @param privateKeyPem The PEM-formatted private key to store temporarily
     */
    fun storePendingPrivateKey(privateKeyPem: String) {
        try {
            prefs.edit()
                .putString(KEY_PENDING_PRIVATE_KEY, privateKeyPem)
                .putLong(KEY_PENDING_TIMESTAMP, System.currentTimeMillis())
                .apply()
            Log.d(TAG, "Stored pending private key for export")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pending private key", e)
        }
    }

    /**
     * Retrieve pending private key from secure storage.
     * Automatically clears expired keys (older than 24 hours).
     *
     * @return The pending private key PEM string, or null if none exists or expired
     */
    fun getPendingPrivateKey(): String? {
        try {
            val privateKeyPem = prefs.getString(KEY_PENDING_PRIVATE_KEY, null)
            val timestamp = prefs.getLong(KEY_PENDING_TIMESTAMP, 0)

            if (privateKeyPem == null) {
                return null
            }

            // Check if key has expired
            val age = System.currentTimeMillis() - timestamp
            if (age > PENDING_KEY_MAX_AGE_MS) {
                Log.w(TAG, "Pending private key expired, clearing")
                clearPendingPrivateKey()
                return null
            }

            return privateKeyPem
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve pending private key", e)
            return null
        }
    }

    /**
     * Clear the pending private key from storage.
     * Should be called after successful export.
     */
    fun clearPendingPrivateKey() {
        try {
            prefs.edit()
                .remove(KEY_PENDING_PRIVATE_KEY)
                .remove(KEY_PENDING_TIMESTAMP)
                .apply()
            Log.d(TAG, "Cleared pending private key")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear pending private key", e)
        }
    }

    /**
     * Check if there's a pending private key waiting to be exported.
     *
     * @return true if a pending private key exists and hasn't expired
     */
    fun hasPendingPrivateKey(): Boolean {
        return getPendingPrivateKey() != null
    }
}
