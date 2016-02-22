# redshift kms-cse

````
# Things to configure:
- KMS ID endpoint
- S3 bucket


# To test out the java program after modifications, run:
mvn compile exec:java -Dexec.mainClass="com.amazonaws.redshift.S3ClientSideEncryptionWithSymmetricMasterKey" -Dexec.cleanupDaemonThreads="false"
mvn compile exec:java -Dexec.mainClass="com.amazonaws.redshift.dataKeyGenerator" -Dexec.cleanupDaemonThreads="false"

# Notes
- keys will persist to /tmp in a linux machine

```
