package pl.edu.agh;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.String;
import java.security.interfaces.RSAPrivateKey;


public class Main {

    private static final int KEY_SIZE = 4096;
    private static final String[] testFiles = { "512b", "512kB", "4MB", "32MB", "64MB", "128MB"};
    private static final String privateKey = "rsa.priv";
    private static final String publicKey = "rsa.pub";

    public static void main(String[] args) {

        generateKeys();

        for (String testFile : testFiles) {
            // symetric
            //SymetricCipher symetricCipher = new SymetricCipher(testFiles[5]);
            //symetricCipher.start();

            // asymetric
            byte[] fileBytes = Utils.getBytesFromFile("tmp/" + testFile);
            encryptAsymetricFile(testFile, fileBytes);
            decryptAsymetricFile(testFile, fileBytes);
        }
    }

    private static void generateKeys() {
        System.out.println("Generate keys");
        long start = System.nanoTime();
        KeyGen kg = new KeyGen(KEY_SIZE, privateKey, publicKey);
        kg.generateKeys();
        long stop = System.nanoTime();
        System.out.println("Keys are generated with size "+kg.keySize);
        System.out.println("Public exponent is "+kg.keyPair.getPublic().toString());
        RSAPrivateKey r = (RSAPrivateKey) kg.keyPair.getPrivate();
        System.out.println("Private exponent is "+r.getPrivateExponent());
        System.out.println("It took " + (stop-start)/1e9d);
    }

    private static void encryptAsymetricFile(String fileName, byte[] fileBytes) {
        System.out.println("Encrypting!");
        CipherBox cipherBox = new CipherBox();
        cipherBox.loadPrivateKey(privateKey);
        cipherBox.loadPublicKey(publicKey);

        long start = System.currentTimeMillis();
        cipherBox.encrypt(fileBytes);
        long stop = System.currentTimeMillis();
        System.out.println("Encrypt " + fileName + " time: " + (stop-start) + "ms");
    }

    private static void decryptAsymetricFile(String fileName, byte[] fileBytes) {
        System.out.println("Decrypting!");
        CipherBox cipherBox = new CipherBox();
        cipherBox.loadPrivateKey(privateKey);
        cipherBox.loadPublicKey(publicKey);

        long start = System.currentTimeMillis();
        cipherBox.encrypt(fileBytes);
        long stop = System.currentTimeMillis();
        System.out.println("Decrypt " + fileName + " time: " + (stop-start) + "ms");
    }
}
