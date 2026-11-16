package br.com.bry.challenge.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

// Stage 1 file hash was calculated with sha512sum.
// This service is intended for reuse by signing and verification.
public class HashService {
    public enum Algorithm { SHA256, SHA512 }

    public String hash(String source, Algorithm algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(String.valueOf(algorithm));
            return HexFormat.of().formatHex(md.digest(source.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Undefined hash algorithm");
        }
    }

    public String hash(String source) {
        return hash(source, Algorithm.SHA512);
    }


    public static byte[] hash(byte[] source, Algorithm algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(String.valueOf(algorithm));
            return md.digest(source);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Undefined hash algorithm");
        }
    }

    public static byte[] hash(byte[] source) {
        return hash(source, Algorithm.SHA512);
    }
}
