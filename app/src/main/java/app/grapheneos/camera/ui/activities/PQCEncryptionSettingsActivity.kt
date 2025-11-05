package app.grapheneos.camera.ui.activities

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import app.grapheneos.camera.CamConfig
import app.grapheneos.camera.R
import app.grapheneos.camera.crypto.PQKeyManager
import app.grapheneos.camera.databinding.ActivityPqcEncryptionSettingsBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Activity for managing post-quantum encryption settings.
 * Allows users to enable encryption, generate/import keys, and export private keys.
 */
class PQCEncryptionSettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivityPqcEncryptionSettingsBinding
    private lateinit var keyManager: PQKeyManager
    private lateinit var camConfig: CamConfig

    private val PERMISSION_REQUEST_CODE = 1001

    // File picker for importing public key
    private val importKeyLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { importPublicKeyFromUri(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityPqcEncryptionSettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        keyManager = PQKeyManager(this)

        val camConfig = obtainCamConfig(intent)
        if (camConfig == null) {
            finish()
            return
        }
        this.camConfig = camConfig

        setupToolbar()
        setupViews()
        updateStatus()
        checkForPendingPrivateKey()
    }

    private fun setupToolbar() {
        binding.appBar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun setupViews() {
        // Encryption toggle
        binding.encryptionEnabledSwitch.isChecked = camConfig.pqcEncryptionEnabled
        binding.encryptionEnabledSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked && !keyManager.isEncryptionAvailable()) {
                // Can't enable without a key
                binding.encryptionEnabledSwitch.isChecked = false
                showMessage(getString(R.string.generate_key_first))
            } else {
                camConfig.pqcEncryptionEnabled = isChecked
                updateStatus()
                if (isChecked) {
                    showMessage(getString(R.string.encryption_enabled_message))
                }
            }
        }

        // Generate keypair button
        binding.generateKeypairButton.setOnClickListener {
            generateNewKeypair()
        }

        // Import public key button
        binding.importPublicKeyButton.setOnClickListener {
            importKeyLauncher.launch("*/*")
        }

        // Export private key button
        binding.exportPrivateKeyButton.setOnClickListener {
            exportPrivateKey()
        }
    }

    private fun updateStatus() {
        val isConfigured = keyManager.isEncryptionAvailable()

        if (isConfigured) {
            binding.encryptionStatus.text = getString(R.string.encryption_ready)
            binding.encryptionStatus.setTextColor(
                ContextCompat.getColor(this, android.R.color.holo_green_dark)
            )
        } else {
            binding.encryptionStatus.text = getString(R.string.no_key_configured)
            binding.encryptionStatus.setTextColor(
                ContextCompat.getColor(this, android.R.color.holo_orange_dark)
            )
            // Disable encryption if no key
            if (camConfig.pqcEncryptionEnabled) {
                camConfig.pqcEncryptionEnabled = false
                binding.encryptionEnabledSwitch.isChecked = false
            }
        }

        // Enable export button only if there's a key to export (after generation)
        binding.exportPrivateKeyButton.isEnabled = keyManager.hasPendingPrivateKey()
    }

    private fun generateNewKeypair() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.generate_keypair_title)
            .setMessage(R.string.generate_keypair_message)
            .setPositiveButton(R.string.generate) { _, _ ->
                try {
                    val (publicKeyPem, privateKeyPem) = keyManager.generateAndStoreKeyPair()

                    // Store private key securely to survive configuration changes
                    keyManager.storePendingPrivateKey(privateKeyPem)

                    updateStatus()

                    MaterialAlertDialogBuilder(this)
                        .setTitle(R.string.keypair_generated_title)
                        .setMessage(R.string.keypair_generated_message)
                        .setPositiveButton(R.string.export_now) { _, _ ->
                            exportPrivateKey()
                        }
                        .setNegativeButton(R.string.later, null)
                        .show()

                } catch (e: Exception) {
                    showMessage(getString(R.string.keypair_generation_failed, e.message))
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun importPublicKeyFromUri(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val pemContent = reader.use { it.readText() }

            if (keyManager.importPublicKey(pemContent)) {
                // Clear pending private key since we're importing (not generating)
                keyManager.clearPendingPrivateKey()
                updateStatus()
                showMessage(getString(R.string.public_key_imported_successfully))
            } else {
                showMessage(getString(R.string.public_key_import_failed))
            }
        } catch (e: Exception) {
            showMessage(getString(R.string.public_key_import_failed_error, e.message))
        }
    }

    private fun exportPrivateKey() {
        val privateKeyPem = keyManager.getPendingPrivateKey()
        if (privateKeyPem == null) {
            showMessage(getString(R.string.no_private_key_to_export))
            return
        }

        // Check for storage permission on Android < 10
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    PERMISSION_REQUEST_CODE
                )
                return
            }
        }

        doExportPrivateKey(privateKeyPem)
    }

    private fun doExportPrivateKey(privateKeyPem: String) {
        try {
            val filePath = keyManager.exportPrivateKeyToFile(privateKeyPem)
            if (filePath != null) {
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.private_key_exported_title)
                    .setMessage(getString(R.string.private_key_exported_message, filePath))
                    .setPositiveButton(android.R.string.ok, null)
                    .show()

                // Clear pending private key after successful export
                keyManager.clearPendingPrivateKey()
                updateStatus()
            } else {
                showMessage(getString(R.string.private_key_export_failed))
            }
        } catch (e: Exception) {
            showMessage(getString(R.string.private_key_export_failed_error, e.message))
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                keyManager.getPendingPrivateKey()?.let { doExportPrivateKey(it) }
            } else {
                showMessage(getString(R.string.storage_permission_required))
            }
        }
    }

    /**
     * Check for pending private key that hasn't been exported yet.
     * Shows a warning dialog if found, prompting immediate export.
     */
    private fun checkForPendingPrivateKey() {
        if (keyManager.hasPendingPrivateKey()) {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.pending_private_key_title)
                .setMessage(R.string.pending_private_key_message)
                .setPositiveButton(R.string.export_now) { _, _ ->
                    exportPrivateKey()
                }
                .setNegativeButton(R.string.later, null)
                .setCancelable(false)
                .show()
        }
    }

    private fun showMessage(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        private var camConfigId = 0L
        private var staticCamConfig: CamConfig? = null

        private const val INTENT_EXTRA_CAM_CONFIG_ID = "camConfig_id"

        fun start(caller: MainActivity) {
            Intent(caller, PQCEncryptionSettingsActivity::class.java).let {
                camConfigId += 1
                it.putExtra(INTENT_EXTRA_CAM_CONFIG_ID, camConfigId)
                staticCamConfig = caller.camConfig

                caller.startActivity(it)
            }
        }

        private fun obtainCamConfig(intent: Intent): CamConfig? {
            val camConfig = staticCamConfig
            if (camConfigId != intent.getLongExtra(INTENT_EXTRA_CAM_CONFIG_ID, -1)) {
                return null
            }
            return camConfig
        }
    }
}
