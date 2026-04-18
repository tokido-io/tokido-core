package io.tokido.core.totp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.CRC32;
import java.util.zip.DeflaterOutputStream;

/**
 * QR code generator that produces PNG images without java.awt or javax.imageio.
 * Safe for GraalVM native-image — uses only java.util.zip for PNG encoding.
 * <p>
 * The ZXing {@link QRCodeWriter} instance is lazily initialized on first use.
 */
public final class QrCodeGenerator {

    private static volatile QRCodeWriter writer;

    private QrCodeGenerator() {
    }

    private static QRCodeWriter writer() {
        QRCodeWriter w = writer;
        if (w == null) {
            synchronized (QrCodeGenerator.class) {
                w = writer;
                if (w == null) {
                    writer = w = new QRCodeWriter();
                }
            }
        }
        return w;
    }

    /**
     * Generate a QR code PNG and return it as a base64-encoded string.
     *
     * @param content the content to encode (e.g., an otpauth:// URI)
     * @return base64-encoded PNG image
     */
    public static String toPngBase64(String content) {
        try {
            BitMatrix matrix = writer().encode(content, BarcodeFormat.QR_CODE, 300, 300);
            byte[] pngBytes = matrixToPng(matrix);
            return Base64.getEncoder().encodeToString(pngBytes);
        } catch (Exception e) {
            throw new RuntimeException("QR code generation failed", e);
        }
    }

    private static byte[] matrixToPng(BitMatrix matrix) throws IOException {
        int modules = matrix.getWidth();
        int scale = Math.max(1, 300 / modules);
        int img = modules * scale;

        int stride = 1 + img * 3;
        byte[] raw = new byte[img * stride];
        for (int my = 0; my < modules; my++) {
            for (int py = 0; py < scale; py++) {
                int row = my * scale + py;
                raw[row * stride] = 0; // filter: None
                for (int mx = 0; mx < modules; mx++) {
                    byte c = matrix.get(mx, my) ? 0 : (byte) 255;
                    for (int px = 0; px < scale; px++) {
                        int idx = row * stride + 1 + (mx * scale + px) * 3;
                        raw[idx] = c;
                        raw[idx + 1] = c;
                        raw[idx + 2] = c;
                    }
                }
            }
        }

        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (DeflaterOutputStream def = new DeflaterOutputStream(compressed)) {
            def.write(raw);
        }

        ByteArrayOutputStream png = new ByteArrayOutputStream();
        png.write(new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A});
        byte[] ihdr = new byte[13];
        ihdr[0] = (byte) (img >> 24); ihdr[1] = (byte) (img >> 16); ihdr[2] = (byte) (img >> 8); ihdr[3] = (byte) img;
        ihdr[4] = (byte) (img >> 24); ihdr[5] = (byte) (img >> 16); ihdr[6] = (byte) (img >> 8); ihdr[7] = (byte) img;
        ihdr[8] = 8; ihdr[9] = 2;
        writePngChunk(png, new byte[]{'I', 'H', 'D', 'R'}, ihdr);
        writePngChunk(png, new byte[]{'I', 'D', 'A', 'T'}, compressed.toByteArray());
        writePngChunk(png, new byte[]{'I', 'E', 'N', 'D'}, new byte[0]);
        return png.toByteArray();
    }

    private static void writePngChunk(ByteArrayOutputStream out, byte[] type, byte[] data) throws IOException {
        int len = data.length;
        out.write(new byte[]{(byte) (len >> 24), (byte) (len >> 16), (byte) (len >> 8), (byte) len});
        out.write(type);
        out.write(data);
        CRC32 crc = new CRC32();
        crc.update(type);
        crc.update(data);
        long v = crc.getValue();
        out.write(new byte[]{(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v});
    }
}
