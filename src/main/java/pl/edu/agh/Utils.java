package pl.edu.agh;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Utils {

    public static byte[] getBytesFromFile(String fileName) {
        File file = new File(fileName);
        FileInputStream inputStream = null;
        byte[] inputBytes = null;
        try {
            inputStream = new FileInputStream(file);
            inputBytes = new byte[(int) file.length()];
            inputStream.read(inputBytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return inputBytes;
    }

}
