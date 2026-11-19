package io.github.rustclashlabs.rustclash.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed `AndroidKeyStore` AES-256-GCM secret vault for proxy profile YAML,
 * subscription URLs, and bearer credentials at rest.
 */
object AndroidKeystoreVault {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "io.github.rustclashlabs.rustclash.profile_aes256_gcm"
    private const val KEY_ALIAS_VAULT_MASTER = "io.github.rustclashlabs.rustclash.vault_master_wrap_v1"
    private const val PREFS_NAME = "rust_clash_encrypted_vault"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12

    @Synchronized
    private fun getOrCreateSecretKey(alias: String = KEY_ALIAS): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    /**
     * Returns true when the Android hardware/TEE-backed `AndroidKeyStore` provider is available
     * (true on Android devices, false on pure-JVM unit tests).
     */
    fun isKeystoreAvailable(): Boolean = runCatching {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        true
    }.getOrDefault(false)

    /**
     * Wraps a 32-byte Rust `SecretVault` master key using a non-exportable AndroidKeyStore
     * AES-256-GCM key, returning `12-byte IV || ciphertext+tag` or `null` on failure.
     * Invoked via JNI from `crates/proxy-ffi/src/android_jni.rs`.
     */
    fun wrapMasterKey(rawKey: ByteArray): ByteArray? {
        if (rawKey.size != 32) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey(KEY_ALIAS_VAULT_MASTER))
            val iv = cipher.iv ?: return null
            if (iv.size != GCM_IV_BYTES) return null
            val ciphertext = cipher.doFinal(rawKey)
            ByteArray(iv.size + ciphertext.size).apply {
                System.arraycopy(iv, 0, this, 0, iv.size)
                System.arraycopy(ciphertext, 0, this, iv.size, ciphertext.size)
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Unwraps a hardware-wrapped `12-byte IV || ciphertext+tag` master key blob back into the
     * 32-byte Rust `SecretVault` master key, or returns `null` if tampered or unavailable.
     * Invoked via JNI from `crates/proxy-ffi/src/android_jni.rs`.
     */
    fun unwrapMasterKey(wrapped: ByteArray): ByteArray? {
        if (wrapped.size < GCM_IV_BYTES + 16) return null
        return try {
            val iv = wrapped.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = wrapped.copyOfRange(GCM_IV_BYTES, wrapped.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateSecretKey(KEY_ALIAS_VAULT_MASTER),
                GCMParameterSpec(GCM_TAG_BITS, iv),
            )
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            null
        }
    }

    fun putEncryptedString(context: Context, key: String, plaintext: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val encoded = Base64.encodeToString(iv, Base64.NO_WRAP) + ":" +
            Base64.encodeToString(ciphertext, Base64.NO_WRAP)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(key, encoded)
            .apply()
    }

    fun getDecryptedString(context: Context, key: String): String? {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(key, null) ?: return null
        val sep = raw.indexOf(':')
        if (sep <= 0) return null
        return try {
            val iv = Base64.decode(raw.substring(0, sep), Base64.NO_WRAP)
            val ciphertext = Base64.decode(raw.substring(sep + 1), Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateSecretKey(),
                GCMParameterSpec(GCM_TAG_BITS, iv),
            )
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}
