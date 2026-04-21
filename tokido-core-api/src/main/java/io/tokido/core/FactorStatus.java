package io.tokido.core;

import java.util.Map;

/**
 * Status of a user's enrollment in a specific factor.
 *
 * @param enrolled   whether the user has an enrollment record
 * @param confirmed  whether the enrollment has been confirmed (always true for factors that don't require confirmation)
 * @param attributes factor-specific attributes. Keys and value types are defined by each factor provider.
 *
 *                   <h2>Built-in factor attribute keys</h2>
 *                   <p>The built-in providers use the following keys:
 *                   <ul>
 *                     <li>TOTP ({@code factorType="totp"}):
 *                       <ul>
 *                         <li>{@code createdAt} — {@link Long} epoch-millis timestamp</li>
 *                         <li>{@code lastUsedAt} — {@link Long} epoch-millis timestamp; absent until first successful verification</li>
 *                       </ul>
 *                     </li>
 *                     <li>Recovery ({@code factorType="recovery"}):
 *                       <ul>
 *                         <li>{@code codesRemaining} — {@link Integer} remaining recovery codes</li>
 *                         <li>{@code createdAt} — {@link Long} epoch-millis timestamp</li>
 *                         <li>{@code lastUsedAt} — {@link Long} epoch-millis timestamp; absent until first successful verification</li>
 *                       </ul>
 *                     </li>
 *                   </ul>
 */
public record FactorStatus(boolean enrolled, boolean confirmed, Map<String, Object> attributes) {

    public static FactorStatus notEnrolled() {
        return new FactorStatus(false, false, Map.of());
    }
}
