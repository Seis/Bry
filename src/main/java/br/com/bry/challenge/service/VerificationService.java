package br.com.bry.challenge.service;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import br.com.bry.challenge.dto.VerificationChecks;
import br.com.bry.challenge.dto.VerificationResult;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class VerificationService {
    private final X509Certificate rootCertificate;
    private final List<X509Certificate> intermediateCertificates;
    private final Clock clock;

    public VerificationService(X509Certificate rootCertificate,
                               List<X509Certificate> intermediateCertificates, Clock clock) {
        this.rootCertificate = Objects.requireNonNull(rootCertificate, "rootCertificate must not be null");
        this.intermediateCertificates = List.copyOf(intermediateCertificates);
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public VerificationResult verify(byte[] cms)
            throws CMSException, CertificateException, OperatorCreationException {
        CMSSignedData signedData = parseCms(cms);
        byte[] content = readAttachedContent(signedData);
        SignerInformation signer = readSingleSigner(signedData);
        X509CertificateHolder holder = readSignerCertificate(signedData, signer);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(provider).getCertificate(holder);

        boolean integrityValid = verifyIntegrity(signer, certificate, provider);
        String signerName = readSignerName(holder);
        Instant signingTime = readSigningTime(signer);
        String hashAlgorithm = MessageDigestUtils.getDigestName(signer.getDigestAlgorithmID().getAlgorithm());
        String documentHash = hashDocument(content, hashAlgorithm, provider);
        VerificationChecks checks = checkCertificateAndDates(certificate, integrityValid, signingTime);

        return new VerificationResult(integrityValid, checks.certificateTrusted(), signerName, signingTime,
                documentHash, hashAlgorithm, checks, describeChecks(checks));
    }

    private static CMSSignedData parseCms(byte[] cms) throws CMSException {
        if (cms == null) {
            throw new IllegalArgumentException("cms must not be null");
        }
        try {
            return new CMSSignedData(cms);
        } catch (IllegalArgumentException | ClassCastException e) {
            throw new CMSException("Invalid CMS structure", e);
        }
    }

    private static byte[] readAttachedContent(CMSSignedData signedData) throws CMSException {
        requireCms(signedData.getSignedContent() != null, "Attached CMS content is required");
        Object content = signedData.getSignedContent().getContent();
        requireCms(content instanceof byte[], "Attached CMS content must contain document bytes");
        return (byte[]) content;
    }

    private static SignerInformation readSingleSigner(CMSSignedData signedData) throws CMSException {
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        requireCms(signers.size() == 1, "Exactly one signer is required");
        return signers.iterator().next();
    }

    private static X509CertificateHolder readSignerCertificate(CMSSignedData signedData, SignerInformation signer)
            throws CMSException {
        List<X509CertificateHolder> certificates = signedData.getCertificates().getMatches(null).stream()
                .filter(certificate -> signer.getSID().match(certificate)).toList();
        requireCms(certificates.size() == 1, "Exactly one matching signer certificate is required");
        return certificates.get(0);
    }

    private static boolean verifyIntegrity(SignerInformation signer, X509Certificate certificate,
                                           BouncyCastleProvider provider)
            throws CMSException, OperatorCreationException {
        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(provider).build(certificate.getPublicKey()));
        } catch (CMSSignerDigestMismatchException e) {
            return false;
        }
    }

    private static String readSignerName(X509CertificateHolder certificate) throws CMSException {
        return Arrays.stream(certificate.getSubject().getRDNs(BCStyle.CN))
                .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                .filter(attribute -> BCStyle.CN.equals(attribute.getType()))
                .map(attribute -> IETFUtils.valueToString(attribute.getValue()))
                .findFirst().orElseThrow(() -> new CMSException("Signer certificate has no common name"));
    }

    private static Instant readSigningTime(SignerInformation signer) throws CMSException {
        AttributeTable attributes = signer.getSignedAttributes();
        Attribute signingTime = attributes == null ? null : attributes.get(CMSAttributes.signingTime);
        requireCms(signingTime != null && signingTime.getAttrValues().size() == 1,
                "Exactly one signingTime value is required");
        try {
            return Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate().toInstant();
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new CMSException("Invalid signingTime attribute", e);
        }
    }

    private static String hashDocument(byte[] content, String algorithm, BouncyCastleProvider provider)
            throws CMSException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm, provider).digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new CMSException("Unsupported digest algorithm: " + algorithm, e);
        }
    }

    private VerificationChecks checkCertificateAndDates(X509Certificate certificate, boolean integrityValid,
                                                        Instant signingTime) {
        Instant now = clock.instant();
        ChainValidation chain = validateChain(certificate, now);
        return new VerificationChecks(integrityValid, chain.trusted(), chain.currentlyValid(),
                now.isAfter(certificate.getNotAfter().toInstant()),
                now.isBefore(certificate.getNotBefore().toInstant()), signingTime.isAfter(now),
                certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
    }

    private static List<String> describeChecks(VerificationChecks checks) {
        List<String> observations = new ArrayList<>();
        if (!checks.integrityValid()) {
            observations.add("Signature integrity validation failed; signer metadata must not be trusted.");
        }
        if (!checks.chainTrusted()) {
            observations.add("The signer certificate does not chain to the configured trusted root.");
        }
        if (checks.certificateExpired()) {
            observations.add("The signer certificate has expired. This would invalidate date-based certificate validation; status ignores date checks.");
        }
        if (checks.certificateNotYetValid()) {
            observations.add("The signer certificate is not yet valid. This would invalidate date-based certificate validation; status ignores date checks.");
        }
        if (checks.chainTrusted() && !checks.certificateTrusted()
                && !checks.certificateExpired() && !checks.certificateNotYetValid()) {
            observations.add("An issuer certificate is outside its validity period. This would invalidate date-based chain validation; status ignores date checks.");
        }
        if (checks.signingTimeInFuture()) {
            observations.add("The declared signing time is in the future. This would invalidate a signing-time policy; status ignores date checks.");
        }
        return observations;
    }

    private ChainValidation validateChain(X509Certificate certificate, Instant now) {
        List<X509Certificate> candidates = new ArrayList<>(intermediateCertificates);
        candidates.add(certificate);
        List<Instant> validationTimes = new ArrayList<>();
        validationTimes.add(now);
        validationTimes.add(rootCertificate.getNotBefore().toInstant());
        for (X509Certificate candidate : candidates) {
            validationTimes.add(candidate.getNotBefore().toInstant());
        }

        // PKIX always checks dates. Try each validity-interval boundary to separate
        // chain trust from current validity, as required by the API status policy.
        for (Instant instant : validationTimes.stream().distinct().toList()) {
            Date validationTime = Date.from(instant);
            if (!validAt(certificate, validationTime) || !validAt(rootCertificate, validationTime)) {
                continue;
            }
            try {
                X509CertSelector target = new X509CertSelector();
                target.setCertificate(certificate);
                PKIXBuilderParameters parameters = new PKIXBuilderParameters(
                        Set.of(new TrustAnchor(rootCertificate, null)), target);
                parameters.setDate(validationTime);
                // Offline validation; CRL/OCSP requires a separate revocation policy.
                parameters.setRevocationEnabled(false);
                parameters.addCertStore(CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(candidates)));
                PKIXCertPathBuilderResult path = (PKIXCertPathBuilderResult)
                        CertPathBuilder.getInstance("PKIX").build(parameters);
                Date currentTime = Date.from(now);
                boolean currentlyValid = validAt(rootCertificate, currentTime)
                        && path.getCertPath().getCertificates().stream()
                        .allMatch(cert -> validAt((X509Certificate) cert, currentTime));
                return new ChainValidation(true, currentlyValid);
            } catch (CertPathBuilderException e) {
                // Another date may yield a PKIX path through a different intermediate.
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Certificate chain validation is unavailable", e);
            }
        }
        return new ChainValidation(false, false);
    }

    private static boolean validAt(X509Certificate certificate, Date date) {
        try {
            certificate.checkValidity(date);
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
    }

    private static void requireCms(boolean condition, String message) throws CMSException {
        if (!condition) {
            throw new CMSException(message);
        }
    }

    private record ChainValidation(boolean trusted, boolean currentlyValid) {
    }
}
