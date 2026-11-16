# bry

Backend Java challenge for BRy (Grupo Certifica).

## Requirements

- JDK 17.0.21 or a newer update in the Java 17 line.
- Maven Wrapper included; a global Maven installation is optional.
- Spring Boot 3.5.16 and BouncyCastle 1.87.

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
The application starts on port 8080. Endpoints are implemented as the challenge progresses.

Base package: `br.com.bry.challenge`.
Challenge documents and sample resources retain their original filenames and contents.
