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

    internal fun resolveExistingSecretKey(ks: KeyStore, alias: String): SecretKey? {
        if (!ks.containsAlias(alias)) {
            return null
        }
        val existing = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry ?: return null
        return existing.secretKey
    }

    internal fun resolveOrCreateSecretKey(
        ks: KeyStore,
        alias: String,
        generator: () -> SecretKey,
    ): SecretKey {
        if (ks.containsAlias(alias)) {
            val existing = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry
                ?: throw IllegalStateException(
                    "AndroidKeyStore alias '$alias' exists but could not be loaded as SecretKeyEntry; refusing to overwrite existing key",
                )
            return existing.secretKey
        }
        return generator()
    }

    @Synchronized
    private fun getExistingSecretKey(alias: String = KEY_ALIAS): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return resolveExistingSecretKey(ks, alias)
    }

    @Synchronized
    private fun getOrCreateSecretKey(alias: String = KEY_ALIAS): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return resolveOrCreateSecretKey(ks, alias) {
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
            keyGenerator.generateKey()
        }
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
     * Strictly read-only: NEVER creates or overwrites the hardware master key.
     * Invoked via JNI from `crates/proxy-ffi/src/android_jni.rs`.
     */
    fun unwrapMasterKey(wrapped: ByteArray): ByteArray? {
        if (wrapped.size < GCM_IV_BYTES + 16) return null
        return try {
            val secretKey = getExistingSecretKey(KEY_ALIAS_VAULT_MASTER) ?: return null
            val iv = wrapped.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = wrapped.copyOfRange(GCM_IV_BYTES, wrapped.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
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

    /**
     * Removes an encrypted vault entry directly from SharedPreferences without touching Keystore
     * or Cipher APIs.
     */
    fun removeEncryptedKey(context: Context, key: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
    }

    fun getDecryptedString(context: Context, key: String): String? {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(key, null) ?: return null
        val sep = raw.indexOf(':')
        if (sep <= 0) return null
        return try {
            val secretKey = getExistingSecretKey() ?: return null
            val iv = Base64.decode(raw.substring(0, sep), Base64.NO_WRAP)
            val ciphertext = Base64.decode(raw.substring(sep + 1), Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(GCM_TAG_BITS, iv),
            )
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}
