package app.grapheneos.camera.crypto

import android.util.Log
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKEMGenerator
import org.bouncycastle.crypto.engines.ChaCha20Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Post-Quantum Cryptography Manager for encrypting photos with ML-KEM (Kyber).
 *
 * Uses ML-KEM-768 for key encapsulation and ChaCha20-Poly1305 for symmetric encryption.
 * File format:
 *   [MAGIC: 8 bytes "PQCAMENC"]
 *   [VERSION: 4 bytes, current = 1]
 *   [KEM_CIPHERTEXT_LENGTH: 4 bytes]
 *   [KEM_CIPHERTEXT: variable, ~1088 bytes for ML-KEM-768]
 *   [NONCE: 12 bytes]
 *   [ENCRYPTED_DATA + AUTH_TAG: remaining bytes]
 */
object PQCryptoManager {
    private const val TAG = "PQCryptoManager"

    // File format constants
    private const val MAGIC = "PQCAMENC"
    private const val VERSION = 1
    private const val NONCE_SIZE = 12 // ChaCha20-Poly1305 nonce size
    private const val TAG_SIZE = 16 // Poly1305 MAC tag size

    // Use ML-KEM-768 (NIST standardized, 256-bit security level)
    val MLKEM_PARAMETERS = MLKEMParameters.ml_kem_768

    // HKDF info string for key derivation
    private const val HKDF_INFO = "GrapheneOS Camera PQC Photo Encryption v1"

    private val secureRandom = SecureRandom()

    init {
        // Ensure Bouncy Castle provider is available
        try {
            org.bouncycastle.jce.provider.BouncyCastleProvider()
            Log.d(TAG, "Bouncy Castle provider initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Bouncy Castle provider", e)
        }
    }

    /**
     * Generate a new ML-KEM-768 keypair for photo encryption.
     *
     * @return AsymmetricCipherKeyPair containing public and private keys
     */
    fun generateKeyPair(): AsymmetricCipherKeyPair {
        val keyGen = MLKEMKeyPairGenerator()
        keyGen.init(MLKEMKeyGenerationParameters(secureRandom, MLKEM_PARAMETERS))
        val keyPair = keyGen.generateKeyPair()
        Log.d(TAG, "Generated ML-KEM-768 keypair")
        return keyPair
    }

    /**
     * Encrypt photo JPEG bytes using ML-KEM + ChaCha20-Poly1305.
     *
     * @param jpegBytes The JPEG image data to encrypt
     * @param publicKey The ML-KEM public key for encryption
     * @return Encrypted file bytes with header, or null on failure
     */
    fun encryptPhoto(jpegBytes: ByteArray, publicKey: MLKEMPublicKeyParameters): ByteArray? {
        try {
            // Step 1: ML-KEM Key Encapsulation
            val kemGen = MLKEMKEMGenerator(secureRandom)
            val encapsulated: SecretWithEncapsulation = kemGen.generateEncapsulated(publicKey)
            val sharedSecret = encapsulated.secret
            val kemCiphertext = encapsulated.encapsulation

            Log.d(TAG, "ML-KEM encapsulation: ciphertext size=${kemCiphertext.size}, shared secret size=${sharedSecret.size}")

            // Step 2: Derive symmetric key from shared secret using HKDF
            val symmetricKey = deriveKey(sharedSecret, 32) // 256-bit key for ChaCha20

            // Step 3: Generate random nonce
            val nonce = ByteArray(NONCE_SIZE)
            secureRandom.nextBytes(nonce)

            // Step 4: Encrypt JPEG with ChaCha20-Poly1305
            val cipher = ChaCha20Poly1305()
            val keyParam = KeyParameter(symmetricKey)
            val paramsWithIV = ParametersWithIV(keyParam, nonce)
            cipher.init(true, paramsWithIV)

            // ChaCha20-Poly1305 adds 16-byte authentication tag
            val encryptedData = ByteArray(jpegBytes.size + TAG_SIZE)
            var len = cipher.processBytes(jpegBytes, 0, jpegBytes.size, encryptedData, 0)
            len += cipher.doFinal(encryptedData, len)

            Log.d(TAG, "Encrypted photo: input=${jpegBytes.size} bytes, output=${len} bytes (includes auth tag)")

            // Step 5: Build encrypted file format
            val output = ByteArrayOutputStream()

            // Write magic header
            output.write(MAGIC.toByteArray(Charsets.US_ASCII))

            // Write version (4 bytes, little-endian)
            output.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(VERSION).array())

            // Write KEM ciphertext length (4 bytes, little-endian)
            output.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(kemCiphertext.size).array())

            // Write KEM ciphertext
            output.write(kemCiphertext)

            // Write nonce
            output.write(nonce)

            // Write encrypted JPEG + auth tag
            output.write(encryptedData, 0, len)

            val result = output.toByteArray()
            Log.d(TAG, "Created encrypted file: total size=${result.size} bytes")

            // Clear sensitive data
            sharedSecret.fill(0)
            symmetricKey.fill(0)

            return result

        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt photo", e)
            return null
        }
    }

    /**
     * Decrypt photo using ML-KEM private key.
     * This method is primarily for testing; decryption should normally be done
     * by the companion desktop utility.
     *
     * @param encryptedBytes The encrypted file bytes
     * @param privateKey The ML-KEM private key for decryption
     * @return Decrypted JPEG bytes, or null on failure
     */
    fun decryptPhoto(encryptedBytes: ByteArray, privateKey: MLKEMPrivateKeyParameters): ByteArray? {
        try {
            val buffer = ByteBuffer.wrap(encryptedBytes).order(ByteOrder.LITTLE_ENDIAN)

            // Step 1: Verify magic header
            val magic = ByteArray(8)
            buffer.get(magic)
            if (String(magic, Charsets.US_ASCII) != MAGIC) {
                Log.e(TAG, "Invalid magic header")
                return null
            }

            // Step 2: Read version
            val version = buffer.int
            if (version != VERSION) {
                Log.e(TAG, "Unsupported version: $version")
                return null
            }

            // Step 3: Read KEM ciphertext
            val kemCiphertextLen = buffer.int
            val kemCiphertext = ByteArray(kemCiphertextLen)
            buffer.get(kemCiphertext)

            // Step 4: Read nonce
            val nonce = ByteArray(NONCE_SIZE)
            buffer.get(nonce)

            // Step 5: Read encrypted data
            val encryptedData = ByteArray(buffer.remaining())
            buffer.get(encryptedData)

            Log.d(TAG, "Decrypting: KEM ciphertext=${kemCiphertextLen} bytes, encrypted data=${encryptedData.size} bytes")

            // Step 6: ML-KEM Decapsulation
            val kemExtractor = MLKEMKEMExtractor(privateKey)
            val sharedSecret = kemExtractor.extractSecret(kemCiphertext)

            // Step 7: Derive symmetric key
            val symmetricKey = deriveKey(sharedSecret, 32)

            // Step 8: Decrypt with ChaCha20-Poly1305
            val cipher = ChaCha20Poly1305()
            val keyParam = KeyParameter(symmetricKey)
            val paramsWithIV = ParametersWithIV(keyParam, nonce)
            cipher.init(false, paramsWithIV)

            val decryptedData = ByteArray(encryptedData.size - TAG_SIZE)
            var len = cipher.processBytes(encryptedData, 0, encryptedData.size, decryptedData, 0)
            len += cipher.doFinal(decryptedData, len)

            Log.d(TAG, "Decrypted photo: ${decryptedData.size} bytes")

            // Clear sensitive data
            sharedSecret.fill(0)
            symmetricKey.fill(0)

            return decryptedData

        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt photo", e)
            return null
        }
    }

    /**
     * Derive a symmetric key from shared secret using HKDF-SHA256.
     */
    private fun deriveKey(sharedSecret: ByteArray, keyLength: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(sharedSecret, null, HKDF_INFO.toByteArray(Charsets.UTF_8)))
        val derivedKey = ByteArray(keyLength)
        hkdf.generateBytes(derivedKey, 0, keyLength)
        return derivedKey
    }

    /**
     * Get the file extension for encrypted photos.
     */
    fun getEncryptedFileExtension(): String = ".pqcenc"

    /**
     * Check if a file is encrypted (by checking magic header).
     */
    fun isEncryptedFile(data: ByteArray): Boolean {
        if (data.size < 8) return false
        val magic = String(data.copyOfRange(0, 8), Charsets.US_ASCII)
        return magic == MAGIC
    }
}
