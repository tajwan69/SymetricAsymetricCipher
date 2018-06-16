package pl.edu.agh;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SymetricCipher {

    private final String key = "passwordpassword";
    private String filePath = "";

    public SymetricCipher(String fileName) {
        filePath = "tmp/" + fileName;

        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    public void start(){

        File output = new File("encryptedfile");
        File newOutput = new File("decryptedfile");
        if( output.exists() ){
            output.delete();
        }
        if (newOutput.exists()) {
            newOutput.delete();
        }

        long startTime = System.currentTimeMillis();
        encryptFileAndWriteToOutput(key, new File (filePath), output);
        long duration = System.currentTimeMillis() - startTime;
        System.out.println("Encrypt " + filePath + " time: " + duration + "ms");

        startTime = System.currentTimeMillis();
        decryptFileAndWriteToOutput(key, output, newOutput);
        duration = System.currentTimeMillis() - startTime;
        System.out.println("Decrypt " + filePath + " time: " + duration + "ms");
    }

    public static void encryptFileAndWriteToOutput(String key, File file, File output) {
        try {
            encryptionUtilityMethod(Cipher.ENCRYPT_MODE, key, file, output);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }

    public static void decryptFileAndWriteToOutput(String key, File file, File output) {
        try {
            encryptionUtilityMethod(Cipher.DECRYPT_MODE, key, file, output);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }

    public static void encryptionUtilityMethod(int mode, String key, File file, File output) throws CryptoException {
        try {
            KeySpec kspec = new SecretKeySpec(key.getBytes(), "AES");
            SecretKey secretKey = SecretKeyFactory.getInstance("AES").generateSecret(kspec);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(mode, secretKey, new IvParameterSpec(new byte[16]));

            FileInputStream inputStream = new FileInputStream(file);
            byte[] inputBytes = new byte[(int) file.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(output);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (Exception ex) {
            ex.printStackTrace();
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }
}
