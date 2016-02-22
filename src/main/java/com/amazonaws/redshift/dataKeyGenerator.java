package com.amazonaws.redshift;

import java.io.FileWriter;
import java.util.Base64;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

//import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
//import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class dataKeyGenerator {

    private final AWSKMSClient kmsClient;
    private static final String keyDir  = System.getProperty("java.io.tmpdir"); 
    private static final String keyName = "secret.key";

    public dataKeyGenerator() throws IOException {

        kmsClient = getClient();
	String keyId = ""; // "arn:aws:kms:us-east-1:<AWSAccount>/key/<id>"
	GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
	dataKeyRequest.setKeyId(keyId);
	dataKeyRequest.setKeySpec("AES_256");

	GenerateDataKeyResult dataKeyResult = kmsClient.generateDataKey(dataKeyRequest);

	ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
	ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();

        /*X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(plaintextKey.array());
        FileOutputStream keyfos1 = new FileOutputStream(keyDir + "/" + keyName);
        keyfos1.write(x509EncodedKeySpec.getEncoded());
        keyfos1.close();*/

	// We need to take this out and this will persist the unencrypted secret key to the filesystem
        FileWriter keyfos2 = new FileWriter(keyDir + "/" + "secret.key.base64");
        keyfos2.write(Base64.getEncoder().encodeToString(plaintextKey.array()));
        keyfos2.close();
	System.out.println("Base64 unencrypted key persisted to /tmp");

	// This can persist to the filesystem, as it is the encrypted ciphertext blob. 
        FileOutputStream keyfos3 = new FileOutputStream(keyDir + "/" + "secret.key.ciphertextblob");
        keyfos3.write(encryptedKey.array());
        keyfos3.close();
	System.out.println("Encrypted cipherblob persisted to /tmp");

	/*DecryptRequest req = new DecryptRequest().withCiphertextBlob(encryptedKey);
	ByteBuffer plainTextDecrypt = kmsClient.decrypt(req).getPlaintext();
	FileWriter keyfos4 = new FileWriter(keyDir + "/" + "secret.key.base64.decrypted");
        keyfos4.write(Base64.getEncoder().encodeToString(plainTextDecrypt.array()));
        keyfos4.close();*/


    }

    public static void main(String[] args) throws IOException {
        new dataKeyGenerator();
    }

    private AWSKMSClient getClient() {
        //final AWSCredentials creds;

        AWSKMSClient kms = new AWSKMSClient(new DefaultAWSCredentialsProviderChain());
        kms.setEndpoint("https://kms.us-east-1.amazonaws.com");

        return kms;
    }
    
}
