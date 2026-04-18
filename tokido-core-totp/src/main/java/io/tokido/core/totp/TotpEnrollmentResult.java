package io.tokido.core.totp;

import io.tokido.core.EnrollmentResult;

/**
 * Result of TOTP enrollment, containing the data the user needs to set up their authenticator.
 *
 * @param secretUri    otpauth:// URI for authenticator apps
 * @param qrCodeBase64 PNG image of the QR code, base64-encoded
 */
public record TotpEnrollmentResult(String secretUri, String qrCodeBase64) implements EnrollmentResult {
}
