package br.com.bry.challenge.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Standalone hashing for stage 1 and its JUnit tests only.
 * CMS signing and integrity verification calculate their digests through BouncyCastle,
 * so those flows do not call this service or pre-hash their input document.
 */
public class HashService {
    public enum Algorithm { SHA256, SHA512 }

    public String hash(String source, Algorithm algorithm) {
        if (source == null) {
            throw new IllegalArgumentException("source must not be null");
        }
        return HexFormat.of().formatHex(hash(source.getBytes(StandardCharsets.UTF_8), algorithm));
    }

    public String hash(String source) {
        return hash(source, Algorithm.SHA512);
    }


    public static byte[] hash(byte[] source, Algorithm algorithm) {
        if (source == null || algorithm == null) {
            throw new IllegalArgumentException("source and algorithm must not be null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance(String.valueOf(algorithm), new BouncyCastleProvider());
            return md.digest(source);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hash algorithm is unavailable", e);
        }
    }

    public static byte[] hash(byte[] source) {
        return hash(source, Algorithm.SHA512);
    }
}
