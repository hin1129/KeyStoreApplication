package com.example.keystoreapplication
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

//“AES/GCM/NoPadding”
class Decryptor {

    //instance of key-store for decryption
    private val keyStore = KeyStore.getInstance("AndroidKeystore")

    //get secret
    fun forKeyStore() {
        keyStore.load(null)
    }

    //secret-key-entry from key-store to grab secret-key
    val secretKeyEntry :KeyStore.SecretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)

    //
    val secretKey :SecretKey = secretKeyEntry.getSecretKey()

    //
    private val encryptionTransformationType = "AES/GCM/NoPadding"
    val cipher :Cipher = Cipher.getInstance(encryptionTransformationType)
    //specify authentication tag length (highest value = 128), pass IV from encryption process
    val spec :GCMParameterSpec = GCMParameterSpec(128, encryption)

    fun initializeCipherDecryption() {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
    }

    //
    private val decodedData :ByteArray = cipher.doFinal(encryptedData)

    //
    val unencryptedString :String by lazy {
        (decodedData, "UTF-8")
    }




}