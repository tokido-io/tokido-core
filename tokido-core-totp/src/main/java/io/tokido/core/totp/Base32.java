package io.tokido.core.totp;

/**
 * RFC 4648 Base32 encoder. No padding.
 */
public final class Base32 {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32() {
    }

    /**
     * Encode bytes to a Base32 string (no padding).
     */
    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0) {
            sb.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }
}
