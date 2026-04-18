package io.tokido.core.recovery;

/**
 * Configuration for the recovery code factor provider.
 */
public class RecoveryConfig {

    int codeCount = 10;
    int codeLength = 8;
    int bcryptCost = 10;

    public static RecoveryConfig defaults() {
        return new RecoveryConfig();
    }

    public RecoveryConfig codeCount(int codeCount) {
        this.codeCount = codeCount;
        return this;
    }

    public RecoveryConfig codeLength(int codeLength) {
        this.codeLength = codeLength;
        return this;
    }

    public RecoveryConfig bcryptCost(int bcryptCost) {
        this.bcryptCost = bcryptCost;
        return this;
    }

    public int codeCount() { return codeCount; }
    public int codeLength() { return codeLength; }
    public int bcryptCost() { return bcryptCost; }
}
