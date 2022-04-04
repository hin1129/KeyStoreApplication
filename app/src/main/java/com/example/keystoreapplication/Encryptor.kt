package com.example.keystoreapplication
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


//“AES/GCM/NoPadding”
class Encryptor {

    /////////////////////////////////////////////
    //setup

    //create instance of key-generator
    private val keyGenerator : KeyGenerator =
    //use aes algorithm for this key-generator
        //save keys/data in android-key-store
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

    //pass instance into key-generator method
    //specify properties for keys to be generated
    //e.g. key to expire after 1min
    private val keyGenParameterSpec : KeyGenParameterSpec =
        KeyGenParameterSpec.Builder("alias", //pass alias wanted to use
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) //encrypt/decrypt data
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM) //only block modes specified can be used, otherwise rejected
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()

    ///////////////////////////////////////////////////////////////////
    //encrypting data

    //initialize key-generator
    fun initializeKeyGenerator() {
        keyGenerator.init(keyGenParameterSpec)
    }

    //generate secret-key
    private val secretKey : SecretKey = keyGenerator.generateKey()

    //use secret key to initialize cipher object, set encryption transformation type
    private val encryptionTransformationType = "AES/GCM/NoPadding"
    private val cipher :Cipher = Cipher.getInstance(encryptionTransformationType)

    //set cipher to encryption mode, used by secret-key
    fun initializeCipherEncryption() {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    }

    private val iv :Array<Int> = emptyArray()
    //grab reference to cipher IV(for decryption)
    fun forIV() {
        iv = cipher.getIV()
    }

    private val encryption :Array<Int> = emptyArray()
    //return byte array
    fun forEncryption() {
        encryption = textToEncrypt.getBytes("UTF-8"))
    }
}