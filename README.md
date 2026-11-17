# bry

Backend Java challenge for BRy (Grupo Certifica).

## Requirements

- JDK 17.0.21 or a newer update in the Java 17 line.
- Maven Wrapper included; a global Maven installation is optional.
- Spring Boot 3.5.16 and BouncyCastle 1.87.

The project retains Spring Boot 3 as required by the challenge.

For the locally installed JDK:

```bash
export JAVA_HOME="$PWD/.tools/jdk-17"
export PATH="$JAVA_HOME/bin:$PATH"
```

In IntelliJ, select the same JDK for the project and Maven runner.

## Run and test

```bash
./mvnw spring-boot:run
./mvnw test
./mvnw clean verify
java -jar target/bry-1.0-SNAPSHOT.jar
```

The first run needs internet access to download Maven and dependencies.
The application starts on port 8080.
Open `http://localhost:8080/` for the basic test page: upload a document, P12/PFX and
password to sign, then download `.p7s`/Base64 or verify the result on the same page.
Verification uploads accept raw `.p7s` as well as Base64 files; the page converts raw
CMS to Base64 before calling the API. No frontend build or external assets are needed.

Base package: `br.com.bry.challenge`.
Challenge documents and sample resources retain their original filenames and contents.

## Logging

Application logs default to `INFO`. Enable signing diagnostics locally with:

```bash
APP_LOG_LEVEL=DEBUG ./mvnw spring-boot:run
```

Logs include operation stages, byte counts and elapsed time, without document contents,
passwords or private keys. HTTP failures should be logged once at the API exception handler.

## REST API

Both endpoints accept `multipart/form-data`, with or without a trailing slash.

### POST /signature/

Parts: `document` (original file), `pkcs12` (signing key store), and `password`.
The PKCS12 must contain exactly one RSA private key with its RSA certificate; its alias
is discovered automatically. Secret-key entries are ignored, including entries protected
with a different password. Before generating CMS, the service signs and verifies an
internal challenge with SHA-512/RSA to confirm that the private key matches the certificate.
Incompatible signing material returns `400`.
The response is plain-text Base64 containing an attached CMS signature made with SHA-512
and RSA.

```bash
curl --fail-with-body http://localhost:8080/signature/ \
  -F 'document=@src/main/resources/arquivos/doc.txt' \
  -F 'pkcs12=@src/main/resources/pkcs12/certificado_teste_hub.pfx' \
  -F 'password=bry123456' -o signature.base64
```

`bry123456` is the password of the sample PKCS12 supplied with the challenge.

### POST /verify/

Part: `signature`, a file containing the Base64 CMS signature. Plain Base64 and Base64
wrapped with whitespace are accepted. Raw DER and PEM headers are not accepted.

```bash
curl --fail-with-body http://localhost:8080/verify/ \
  -F 'signature=@signature.base64'
```

The JSON response contains:

- `status`: `VALIDO` only when signature integrity and certificate-chain trust both pass.
- `infos`: `signerName` (CN), `signingTime`, `documentHash` (hex), `hashAlgorithm`.
- `checks`: `integrityValid`, `chainTrusted`, `certificateTrusted`, `certificateExpired`,
  `certificateNotYetValid`, `signingTimeInFuture`, `certificateValidFrom`, `certificateValidUntil`.
- `observations`: explanations for failed checks and date-related warnings.

The overall status combines the two checks required in stage 3: signature integrity and
certificate-chain trust. An intact signature from an untrusted certificate returns `INVALIDO`.

By the chosen API policy, date checks are advisory: expired/not-yet-valid certificates
and future signing times do **not** change `status`. `certificateTrusted` reports chain
trust **and current validity**, whereas `chainTrusted` reports a PKIX path to the configured
root at a date when that path was valid. Neither should be inferred solely from `status`.
`signingTime` is a signed claim from the signer, not a trusted timestamp.

The trusted root and intermediate are loaded from `src/main/resources/cadeia/`.
Validation is offline, without CRL/OCSP revocation checks. The clock is injectable for tests;
normal requests use UTC system time.

### Upload limits and errors

Limits: document 5 MiB, PKCS12 1 MiB, Base64 signature 10 MiB, total request 12 MiB.
An empty document can be signed; an empty PKCS12 or signature is rejected.

Malformed requests, Base64, PKCS12, unsupported CMS and incorrect passwords return `400`.
Unsupported media types return `415`, oversized uploads `413`, and unexpected failures
`500`. Errors use `application/problem+json` and do not expose stack traces or passwords.
A parseable CMS with invalid integrity or an untrusted chain returns `200` with `INVALIDO`.

## Stage 1

`HashService` calculates SHA-512 (default) or SHA-256 from original bytes using BouncyCastle.
The byte-array overload returns the raw digest; the String overload returns lowercase hex
for UTF-8 input. The tests read and hash the original `doc.txt` without text conversion.
The expected document digest is checked by `HashServiceTest` and can be independently verified with:

```bash
sha512sum src/main/resources/arquivos/doc.txt
./mvnw -Dtest=HashServiceTest test
```
