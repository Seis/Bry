package br.com.bry.challenge.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import br.com.bry.challenge.exception.InvalidSigningMaterialException;

public class SignatureService {
    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);
    private static final byte[] KEY_PAIR_CHALLENGE =
            "BRy signing key pair validation".getBytes(StandardCharsets.US_ASCII);

    public byte[] sign(byte[] document, byte[] pkcs12, char[] password)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        requireArgument(document, "document");
        requireArgument(pkcs12, "pkcs12");
        requireArgument(password, "password");
        KeyStore store;
        String alias;
        try {
            store = getStore(pkcs12, password);
            List<String> aliases = new ArrayList<>();
            var entries = store.aliases();
            while (entries.hasMoreElements()) {
                String candidate = entries.nextElement();
                if (store.entryInstanceOf(candidate, KeyStore.PrivateKeyEntry.class)
                        && store.getCertificate(candidate) instanceof X509Certificate certificate
                        && "RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
                    Key key = store.getKey(candidate, password);
                    if (key instanceof PrivateKey && "RSA".equalsIgnoreCase(key.getAlgorithm())) {
                        aliases.add(candidate);
                    }
                }
            }
            if (aliases.size() != 1) {
                throw new InvalidKeyException("PKCS12 must contain exactly one RSA private key with a certificate");
            }
            alias = aliases.get(0);
        } catch (IOException | GeneralSecurityException e) {
            throw new InvalidSigningMaterialException(
                    "Invalid PKCS12, password or signing key; exactly one RSA private key is required", e);
        }
        return sign(document, store, alias, password);
    }

    /** Returns attached CMS bytes. Null arguments are rejected with IllegalArgumentException. */
    public byte[] sign(byte[] document, byte[] pkcs12, String alias, char[] password)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        requireArgument(document, "document");
        requireArgument(pkcs12, "pkcs12");
        requireArgument(alias, "alias");
        requireArgument(password, "password");

        return sign(document, getStore(pkcs12, password), alias, password);
    }

    private byte[] sign(byte[] document, KeyStore store, String alias, char[] password)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        long startedAt = System.nanoTime();
        log.debug("Starting attached CMS signing: documentBytes={}, algorithm=SHA512withRSA", document.length);

        PrivateKey pk = getPk(alias, password, store);
        if (!(store.getCertificate(alias) instanceof X509Certificate certificate)) {
            throw new GeneralSecurityException("No X.509 certificate found for alias: " + alias);
        }
        validateKeyPair(pk, certificate);
        log.debug("PKCS12 private key and signer certificate loaded");

        SignerInfoGenerator signerInfo = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(new BouncyCastleProvider())
                .build("SHA512withRSA", pk, certificate);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerInfo);
        generator.addCertificates(new JcaCertStore(List.of(certificate)));

        CMSProcessableByteArray content = new CMSProcessableByteArray(document);
        byte[] result = generator.generate(content, true).getEncoded();
        log.info("Attached CMS signing completed: documentBytes={}, signatureBytes={}, durationMs={}",
                document.length, result.length, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt));
        return result;
    }

    private static void validateKeyPair(PrivateKey privateKey, X509Certificate certificate)
            throws InvalidSigningMaterialException {
        // Prove the pair works with the signing algorithm before generating a CMS.
        try {
            Signature proof = Signature.getInstance("SHA512withRSA", new BouncyCastleProvider());
            proof.initSign(privateKey);
            proof.update(KEY_PAIR_CHALLENGE);
            byte[] signature = proof.sign();
            proof.initVerify(certificate.getPublicKey());
            proof.update(KEY_PAIR_CHALLENGE);
            if (!proof.verify(signature)) {
                throw new InvalidKeyException("Private key does not match the signer certificate");
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidSigningMaterialException(
                    "RSA private key and certificate must form a usable signing key pair", e);
        }
    }

    private static void requireArgument(Object value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
    }

    private static PrivateKey getPk(String alias, char[] password, KeyStore store)
            throws GeneralSecurityException {
        if (!store.containsAlias(alias)) {
            throw new GeneralSecurityException("Alias not found: " + alias);
        }

        Key key;
        try {
            key = store.getKey(alias, password);
        } catch (UnrecoverableKeyException cause) {
            UnrecoverableKeyException error = new UnrecoverableKeyException("Unable to recover private key for alias: " + alias);
            error.initCause(cause);
            throw error;
        }

        if (!(key instanceof PrivateKey privateKey)) {
            throw new InvalidKeyException("No private key found for alias: " + alias);
        }
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("An RSA private key is required");
        }
        return privateKey;
    }

    private static KeyStore getStore(byte[] pkcs12, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), password);
        return store;
    }
}
