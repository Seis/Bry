package br.com.bry.challenge.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

public class Utils {
    public static byte[] readResource(String path) throws IOException {
        try (InputStream input = Utils.class.getClassLoader().getResourceAsStream(path)) {
            if (input == null) {
                throw new IOException("Resource not found: " + path);
            }
            return input.readAllBytes();
        }
    }
}
