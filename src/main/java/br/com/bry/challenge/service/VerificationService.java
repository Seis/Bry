package br.com.bry.challenge.service;

import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import br.com.bry.challenge.dto.VerificationResult;
import br.com.bry.challenge.dto.VerificationChecks;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.RDN;
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
        if (cms == null) {
            throw new IllegalArgumentException("cms must not be null");
        }

        CMSSignedData signedData = new CMSSignedData(cms);
        if (signedData.getSignedContent() == null) {
            throw new CMSException("Attached CMS content is required");
        }
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.size() != 1) {
            throw new CMSException("Exactly one signer is required");
        }
        SignerInformation signer = signers.iterator().next();
        List<X509CertificateHolder> certificates = signedData.getCertificates().getMatches(null).stream()
                .filter(certificate -> signer.getSID().match(certificate)).toList();
        if (certificates.size() != 1) {
            throw new CMSException("Exactly one matching signer certificate is required");
        }
        X509CertificateHolder holder = certificates.get(0);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(provider).getCertificate(holder);

        boolean integrityValid;
        try {
            integrityValid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(provider).build(certificate.getPublicKey()));
        } catch (CMSSignerDigestMismatchException e) {
            integrityValid = false;
        }

        RDN[] commonNames = holder.getSubject().getRDNs(BCStyle.CN);
        if (commonNames.length == 0) {
            throw new CMSException("Signer certificate has no common name");
        }
        String signerName = IETFUtils.valueToString(commonNames[0].getFirst().getValue());
        Instant signingTime = readSigningTime(signer);
        String hashAlgorithm = MessageDigestUtils.getDigestName(signer.getDigestAlgorithmID().getAlgorithm());
        byte[] content = (byte[]) signedData.getSignedContent().getContent();
        String documentHash;
        try {
            documentHash = HexFormat.of().formatHex(MessageDigest.getInstance(hashAlgorithm, provider).digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new CMSException("Unsupported digest algorithm: " + hashAlgorithm, e);
        }

        Instant now = clock.instant();
        ChainValidation chain = validateChain(certificate, now);
        boolean expired = now.isAfter(certificate.getNotAfter().toInstant());
        boolean notYetValid = now.isBefore(certificate.getNotBefore().toInstant());
        boolean futureSigningTime = signingTime.isAfter(now);
        List<String> observations = new ArrayList<>();
        if (!integrityValid) {
            observations.add("Signature integrity validation failed; signer metadata must not be trusted.");
        }
        if (!chain.trusted()) {
            observations.add("The signer certificate does not chain to the configured trusted root.");
        }
        if (expired) {
            observations.add("The signer certificate has expired. This would invalidate date-based certificate validation; status ignores date checks.");
        }
        if (notYetValid) {
            observations.add("The signer certificate is not yet valid. This would invalidate date-based certificate validation; status ignores date checks.");
        }
        if (chain.trusted() && !chain.currentlyValid() && !expired && !notYetValid) {
            observations.add("An issuer certificate is outside its validity period. This would invalidate date-based chain validation; status ignores date checks.");
        }
        if (futureSigningTime) {
            observations.add("The declared signing time is in the future. This would invalidate a signing-time policy; status ignores date checks.");
        }
        VerificationChecks checks = new VerificationChecks(integrityValid, chain.trusted(), chain.currentlyValid(),
                expired, notYetValid, futureSigningTime,
                certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        return new VerificationResult(integrityValid, chain.currentlyValid(), signerName, signingTime,
                documentHash, hashAlgorithm, checks, observations);
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
                if (currentlyValid) {
                    return new ChainValidation(true, true);
                }
                return new ChainValidation(true, false);
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

    private record ChainValidation(boolean trusted, boolean currentlyValid) {
    }

    private static Instant readSigningTime(SignerInformation signer) throws CMSException {
        AttributeTable attributes = signer.getSignedAttributes();
        Attribute signingTime = attributes == null ? null : attributes.get(CMSAttributes.signingTime);
        if (signingTime == null || signingTime.getAttrValues().size() != 1) {
            throw new CMSException("Exactly one signingTime value is required");
        }
        try {
            return Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate().toInstant();
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new CMSException("Invalid signingTime attribute", e);
        }
    }
}
