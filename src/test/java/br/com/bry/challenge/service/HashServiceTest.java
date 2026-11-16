package br.com.bry.challenge.service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashServiceTest {

    private final HashService service = new HashService();

    @Test
    @DisplayName("Stage 1: compute the SHA-512 digest of resources/arquivos/doc.txt")
    void stage1ComputesSha512OfChallengeDocument() throws Exception {
        try (InputStream input = HashServiceTest.class.getClassLoader()
                .getResourceAsStream("arquivos/doc.txt")) {
            assertNotNull(input, "Missing challenge document");
            byte[] expected = HexFormat.of().parseHex(
                    "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35");

            assertArrayEquals(expected, HashService.hash(input.readAllBytes(), HashService.Algorithm.SHA512));
        }
    }

    @ParameterizedTest(name = "{1}: {0}")
    @MethodSource("knownVectors")
    void computesExpectedHash(String scenario, HashService.Algorithm algorithm,
                            String input, String expected) {
        assertEquals(expected, service.hash(input, algorithm), scenario);
    }

    private static Stream<Arguments> knownVectors() {
        return Stream.of(
                Arguments.of("empty input", HashService.Algorithm.SHA256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                Arguments.of("abc vector", HashService.Algorithm.SHA256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Arguments.of("UTF-8 accents", HashService.Algorithm.SHA256, "Olá, ação!", "aec43d332557088e0b57670e79af6691edce99d2a16df1703faf5c975a138f4a"),
                Arguments.of("leading zero in digest", HashService.Algorithm.SHA256, "zero-320", "00d37eedb5377d2e9b6b9a6cf243c546056fdb1cbc5fe9261c057b3cf0d068b0"),
                Arguments.of("empty input", HashService.Algorithm.SHA512, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
                Arguments.of("abc vector", HashService.Algorithm.SHA512, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
                Arguments.of("UTF-8 accents", HashService.Algorithm.SHA512, "Olá, ação!", "56f0f22fed7b4bbea3ba8d6a2c23bae10de60b30a47d18ea678dc5840d90a6428fe24f9d4a2cfb2563c7b0fce1bec5de8dc1a3e6e1f18f01ce59716548ada745"),
                Arguments.of("leading zero in digest", HashService.Algorithm.SHA512, "zero-540", "00eb295eeeb43c044ab75fe21c2e7c8a677e712ad799ab50f46a60ee409b92df6cf27d484877bcec0b52e0ae7ffcfab111327224f7bcc5ce5c610fae3b0bf2d2")
        );
    }

    @Test
    void defaultsToSha512() {
        assertEquals(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                service.hash("abc"));
    }

    @ParameterizedTest
    @EnumSource(HashService.Algorithm.class)
    void returnsTwoHexCharactersPerByte(HashService.Algorithm algorithm) {
        int length = algorithm == HashService.Algorithm.SHA512 ? 128 : 64;
        String result = service.hash("abc", algorithm);

        assertEquals(length, result.length(), "Hex must represent every digest byte");
        assertTrue(result.matches("[0-9a-f]+"),
                "Expected lowercase hex without brackets or separators");
    }

    @ParameterizedTest
    @EnumSource(HashService.Algorithm.class)
    void preservesWhitespaceAndLineEndings(HashService.Algorithm algorithm) {
        String withoutWhitespace = service.hash("abc", algorithm);

        assertNotEquals(withoutWhitespace, service.hash(" abc", algorithm), "Preserve leading spaces");
        assertNotEquals(withoutWhitespace, service.hash("abc ", algorithm), "Preserve trailing spaces");
        assertNotEquals(withoutWhitespace, service.hash("abc\n", algorithm), "Preserve trailing newline");
        assertNotEquals(service.hash("abc\n", algorithm), service.hash("abc\r\n", algorithm),
                "LF and CRLF represent different content");
    }

    @ParameterizedTest(name = "Raw digest {1}: {0}")
    @MethodSource("knownVectors")
    void computesExpectedRawDigest(String scenario, HashService.Algorithm algorithm,
                                  String input, String expected) {
        assertArrayEquals(HexFormat.of().parseHex(expected),
                HashService.hash(input.getBytes(StandardCharsets.UTF_8), algorithm), scenario);
    }

    @Test
    void rawDigestDefaultsToSha512() {
        byte[] expected = HexFormat.of().parseHex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        assertArrayEquals(expected, HashService.hash("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @ParameterizedTest
    @MethodSource("binaryVectors")
    void hashesBinaryContentWithoutTextConversion(HashService.Algorithm algorithm, String expected) {
        byte[] content = {0, (byte) 0xff, 13, 10, (byte) 0x80};

        assertArrayEquals(HexFormat.of().parseHex(expected), HashService.hash(content, algorithm));
    }

    private static Stream<Arguments> binaryVectors() {
        return Stream.of(
                Arguments.of(HashService.Algorithm.SHA256, "672098eecaca353d3dee05da38b00e81d3dede461ea74c33d9d3cea60ae9a500"),
                Arguments.of(HashService.Algorithm.SHA512, "ef710cb94a70156859122021356d8d3e41eeb01e8c2a56021118dc29d7e19e7886a71791a1280c83730958728e31a0c87946ad4df1c31e27b83d1bd82ba86780")
        );
    }

    @Test
    void rejectsNullSourceAndAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> HashService.hash((byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> HashService.hash(new byte[0], null));
        assertThrows(IllegalArgumentException.class, () -> service.hash((String) null));
    }
}
