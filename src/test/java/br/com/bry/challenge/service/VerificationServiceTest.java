package br.com.bry.challenge.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import br.com.bry.challenge.dto.VerificationResult;
import br.com.bry.challenge.util.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

class VerificationServiceTest {
    private static final Instant VALIDATION_TIME = Instant.parse("2026-06-01T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(VALIDATION_TIME, ZoneOffset.UTC);
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static byte[] pkcs12;
    private static String alias;
    private static PrivateKey privateKey;
    private static X509Certificate certificate;
    private static X509Certificate root;
    private static X509Certificate intermediate;
    private static KeyPair unrelatedKeys;
    private static X509Certificate unrelatedRoot;
    private static byte[] document;
    private static byte[] validCms;

    @Test
    @DisplayName("Stage 3: verify signature integrity, certificate trust and signer information")
    void stage3VerifiesIntegrityTrustAndSignerInformation() throws Exception {
        VerificationResult result = service().verify(validCms);

        assertAll(
                () -> assertTrue(result.integrityValid()),
                () -> assertTrue(result.certificateTrusted()),
                () -> assertTrue(result.checks().chainTrusted()),
                () -> assertEquals("HUB2 TESTES", result.signerName()),
                () -> assertEquals(VALIDATION_TIME, result.signingTime()),
                () -> assertEquals("SHA-512", result.hashAlgorithm()),
                () -> assertEquals("dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35", result.documentHash()));
    }

    @BeforeAll
    static void prepareIndependentFixtures() throws Exception {
        char[] password = "bry123456".toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        pkcs12 = Utils.readResource("pkcs12/certificado_teste_hub.pfx");
        store.load(new ByteArrayInputStream(pkcs12), password);
        alias = store.aliases().nextElement();
        privateKey = (PrivateKey) store.getKey(alias, password);
        certificate = (X509Certificate) store.getCertificate(alias);
        root = readCertificate("cadeia/ac_raiz_bry_v3.cer");
        intermediate = readCertificate("cadeia/ac_bry_servidor_seguro_v3.cer");
        document = Utils.readResource("arquivos/doc.txt");
        validCms = generateCms(document, privateKey, certificate, true, true);

        // Check fixture validity independently of the service under test.
        var cms = new CMSSignedData(validCms);
        assertTrue(cms.getSignerInfos().getSigners().iterator().next().verify(
                new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER).build(certificate.getPublicKey())));
        var parameters = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
        parameters.setDate(Date.from(VALIDATION_TIME));
        parameters.setRevocationEnabled(false);
        var path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(certificate, intermediate));
        CertPathValidator.getInstance("PKIX").validate(path, parameters);

        var keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        unrelatedKeys = keyGenerator.generateKeyPair();
        var name = new X500Name("CN=Untrusted Test Root");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(Instant.parse("2020-01-01T00:00:00Z")),
                Date.from(Instant.parse("2040-01-01T00:00:00Z")), name, unrelatedKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        unrelatedRoot = new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA512withRSA").setProvider(PROVIDER).build(unrelatedKeys.getPrivate())));
    }

    @Test
    void verifiesCmsProducedBySignatureService() throws Exception {
        byte[] cms = new SignatureService().sign(document, pkcs12, alias, "bry123456".toCharArray());
        VerificationResult result = service().verify(cms);

        assertAll(() -> assertTrue(result.integrityValid()),
                () -> assertTrue(result.certificateTrusted()));
    }

    @Test
    void extractsSignerNameSigningTimeDocumentHashAndAlgorithm() throws Exception {
        VerificationResult result = service().verify(validCms);

        assertAll(
                () -> assertEquals("HUB2 TESTES", result.signerName()),
                () -> assertEquals(VALIDATION_TIME, result.signingTime()),
                () -> assertEquals("dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35", result.documentHash()),
                () -> assertEquals("SHA-512", result.hashAlgorithm()));
    }

    @Test
    void extractsCommonNameFromMultiValuedRdn() throws Exception {
        String commonName = "Multi-valued signer common name";
        X500Name subject = new X500Name(new RDN[]{new RDN(new AttributeTypeAndValue[]{
                new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("X")),
                new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(commonName))})});
        var builder = new JcaX509v3CertificateBuilder(subject, BigInteger.TWO,
                Date.from(Instant.parse("2020-01-01T00:00:00Z")),
                Date.from(Instant.parse("2040-01-01T00:00:00Z")), subject, unrelatedKeys.getPublic());
        var multiValuedCertificate = new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA512withRSA")
                        .setProvider(PROVIDER).build(unrelatedKeys.getPrivate())));
        byte[] cms = generateCms(document, unrelatedKeys.getPrivate(), multiValuedCertificate, true, true);

        VerificationResult result = service().verify(cms);

        assertTrue(result.integrityValid());
        assertEquals(commonName, result.signerName());
    }

    @Test
    void detectsModifiedEncapsulatedContent() throws Exception {
        SignedData original = signedData(validCms);
        var changedContent = new ContentInfo(CMSObjectIdentifiers.data,
                new DEROctetString("modified document".getBytes(StandardCharsets.UTF_8)));
        byte[] modified = encode(new SignedData(original.getDigestAlgorithms(), changedContent,
                original.getCertificates(), original.getCRLs(), original.getSignerInfos()));

        assertFalse(service().verify(modified).integrityValid());
    }

    @Test
    void detectsModifiedSignatureBytes() throws Exception {
        SignedData original = signedData(validCms);
        SignerInfo signer = SignerInfo.getInstance(original.getSignerInfos().getObjectAt(0));
        byte[] signature = signer.getEncryptedDigest().getOctets().clone();
        signature[0] ^= 1;
        var changedSigner = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                new DEROctetString(signature), signer.getUnauthenticatedAttributes());
        byte[] modified = encode(new SignedData(original.getDigestAlgorithms(), original.getEncapContentInfo(),
                original.getCertificates(), original.getCRLs(), new DERSet(changedSigner)));

        assertFalse(service().verify(modified).integrityValid());
    }

    @Test
    void separatesCryptographicIntegrityFromRootTrust() throws Exception {
        var service = new VerificationService(unrelatedRoot, List.of(intermediate), CLOCK);
        VerificationResult result = service.verify(validCms);

        assertAll(() -> assertTrue(result.integrityValid()),
                () -> assertFalse(result.certificateTrusted()));
    }

    @Test
    void doesNotTrustASelfSignedCertificateJustBecauseItIsEmbedded() throws Exception {
        byte[] cms = generateCms(document, unrelatedKeys.getPrivate(), unrelatedRoot, true, true);
        VerificationResult result = service().verify(cms);

        assertAll(() -> assertTrue(result.integrityValid()),
                () -> assertFalse(result.certificateTrusted()));
    }

    @Test
    void rejectsIncompleteCertificateChain() throws Exception {
        var service = new VerificationService(root, List.of(), CLOCK);
        VerificationResult result = service.verify(validCms);

        assertAll(() -> assertTrue(result.integrityValid()),
                () -> assertFalse(result.certificateTrusted()));
    }

    @ParameterizedTest(name = "Certificate validity at {0}")
    @MethodSource("invalidValidationTimes")
    void checksCertificateValidityAtTheConfiguredTime(Instant validationTime, boolean expired, boolean notYetValid) throws Exception {
        var service = new VerificationService(root, List.of(intermediate),
                Clock.fixed(validationTime, ZoneOffset.UTC));
        VerificationResult result = service.verify(validCms);

        assertAll(() -> assertTrue(result.integrityValid()),
                () -> assertFalse(result.certificateTrusted()),
                () -> assertTrue(result.checks().chainTrusted()),
                () -> assertEquals(expired, result.checks().certificateExpired()),
                () -> assertEquals(notYetValid, result.checks().certificateNotYetValid()),
                () -> assertFalse(result.observations().isEmpty()));
    }

    private static Stream<Arguments> invalidValidationTimes() {
        return Stream.of(Arguments.of(Instant.parse("2020-01-01T00:00:00Z"), false, true),
                Arguments.of(Instant.parse("2030-01-01T00:00:00Z"), true, false));
    }

    @ParameterizedTest(name = "Malformed CMS: {0}")
    @MethodSource("malformedInputs")
    void rejectsMalformedCms(String scenario, byte[] input) {
        assertThrows(CMSException.class, () -> service().verify(input), scenario);
    }

    private static Stream<Arguments> malformedInputs() throws IOException {
        return Stream.of(Arguments.of("empty input", new byte[0]),
                Arguments.of("random bytes", new byte[]{1, 2, 3, 4}),
                Arguments.of("plain text", "not CMS".getBytes(StandardCharsets.UTF_8)),
                Arguments.of("ASN.1 integer instead of ContentInfo", new byte[]{2, 1, 1}),
                Arguments.of("data content instead of SignedData", new ContentInfo(
                        CMSObjectIdentifiers.data, new DEROctetString(new byte[]{1, 2, 3})).getEncoded()));
    }

    @Test
    void rejectsNullCms() {
        assertThrows(IllegalArgumentException.class, () -> service().verify(null));
    }

    @Test
    void rejectsDetachedCmsWithoutEmbeddedDocument() throws Exception {
        byte[] detached = generateCms(document, privateKey, certificate, false, true);

        assertThrows(CMSException.class, () -> service().verify(detached));
    }

    @Test
    void rejectsCmsWithoutSigner() throws Exception {
        var generator = new CMSSignedDataGenerator();
        generator.addCertificates(new JcaCertStore(List.of(certificate)));
        byte[] unsigned = generator.generate(new CMSProcessableByteArray(document), true).getEncoded();

        assertThrows(CMSException.class, () -> service().verify(unsigned));
    }

    @Test
    void rejectsCmsWithoutSignerCertificate() throws Exception {
        byte[] cms = generateCms(document, privateKey, certificate, true, false);

        assertThrows(CMSException.class, () -> service().verify(cms));
    }

    @Test
    void rejectsMultipleSignersInsteadOfSilentlyPickingOne() throws Exception {
        var generator = generatorWithSigner(privateKey, certificate);
        generator.addSignerInfoGenerator(signerInfo(unrelatedKeys.getPrivate(), unrelatedRoot));
        generator.addCertificates(new JcaCertStore(List.of(certificate, unrelatedRoot)));
        byte[] cms = generator.generate(new CMSProcessableByteArray(document), true).getEncoded();

        assertThrows(CMSException.class, () -> service().verify(cms));
    }

    private static VerificationService service() {
        return new VerificationService(root, List.of(intermediate), CLOCK);
    }

    private static X509Certificate readCertificate(String resource) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Utils.readResource(resource)));
    }

    private static byte[] generateCms(byte[] content, PrivateKey key, X509Certificate signer,
                                      boolean attached, boolean includeCertificate) throws Exception {
        CMSSignedDataGenerator generator = generatorWithSigner(key, signer);
        if (includeCertificate) {
            generator.addCertificates(new JcaCertStore(List.of(signer)));
        }
        return generator.generate(new CMSProcessableByteArray(content), attached).getEncoded();
    }

    private static CMSSignedDataGenerator generatorWithSigner(PrivateKey key, X509Certificate signer)
            throws Exception {
        var generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerInfo(key, signer));
        return generator;
    }

    private static org.bouncycastle.cms.SignerInfoGenerator signerInfo(PrivateKey key,
                                                                      X509Certificate signer) throws Exception {
        var attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(Date.from(VALIDATION_TIME)))));
        return new JcaSimpleSignerInfoGeneratorBuilder().setProvider(PROVIDER)
                .setSignedAttributeGenerator(new AttributeTable(attributes))
                .build("SHA512withRSA", key, signer);
    }

    private static SignedData signedData(byte[] cms) throws Exception {
        return SignedData.getInstance(new CMSSignedData(cms).toASN1Structure().getContent());
    }

    private static byte[] encode(SignedData data) throws Exception {
        return new ContentInfo(CMSObjectIdentifiers.signedData, data).getEncoded();
    }
}
