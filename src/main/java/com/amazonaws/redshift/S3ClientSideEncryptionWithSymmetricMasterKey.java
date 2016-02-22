package com.amazonaws.redshift;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.UUID;
import java.nio.ByteBuffer;
import java.io.FileWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;

//import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.ListVersionsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.S3VersionSummary;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.VersionListing;

import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;


import java.security.spec.X509EncodedKeySpec;

public class S3ClientSideEncryptionWithSymmetricMasterKey {
    private static final String masterKeyDir = System.getProperty("java.io.tmpdir");
    private static final String bucketName = "fabtan-redshift";
    private static final String objectKey = "encrypted.txt";
    private static final String keyName = "secret.key.ciphertextblob";
    private static final String uploadFileName = "/var/www/java/general/kms/test.csv";

    public static void main(String[] args) throws Exception {

	// Read the encrypted ciphertext blob
        File keyFile = new File(masterKeyDir + "/" + keyName);
        FileInputStream keyfis = new FileInputStream(keyFile);
        byte[] PrivateKeyEncrypted = new byte[(int)keyFile.length()];
        keyfis.read(PrivateKeyEncrypted);
        keyfis.close();

        ByteBuffer privateKeyEncryptedBuf = ByteBuffer.wrap(PrivateKeyEncrypted);

	// Decrypt the ciphertext blob via KMS
        //AWSKMSClient kmsClient = new AWSKMSClient(new ProfileCredentialsProvider());
        AWSKMSClient kmsClient = new AWSKMSClient(new DefaultAWSCredentialsProviderChain());
        kmsClient.setEndpoint("https://kms.us-east-1.amazonaws.com");

        DecryptRequest decryptRequest = new DecryptRequest()
                               .withCiphertextBlob(privateKeyEncryptedBuf);
        ByteBuffer mySymmetricKey = kmsClient.decrypt(decryptRequest).getPlaintext();

	// Encode the data key
        //X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(mySymmetricKey.array());
        //SecretKey mySymmetricKeyEncoded = new SecretKeySpec(x509EncodedKeySpec.getEncoded(), "AES");
        SecretKey mySymmetricKeyEncoded = new SecretKeySpec(mySymmetricKey.array(), "AES");

        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(
                mySymmetricKeyEncoded);

	// Invoke S3 EncyptionClient  with Encryption Materials
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new DefaultAWSCredentialsProviderChain(),
                new StaticEncryptionMaterialsProvider(encryptionMaterials));

	// Upload the file
	try {
        File file = new File(uploadFileName);
    	encryptionClient.putObject(new PutObjectRequest(bucketName, objectKey,
                  file));
        
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which " +
            		"means your request made it " +
                    "to Amazon S3, but was rejected with an error response" +
                    " for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which " +
            		"means the client encountered " +
                    "an internal error while trying to " +
                    "communicate with S3, " +
                    "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
        }
	System.out.println("S3 file uploaded!");

    }

}
