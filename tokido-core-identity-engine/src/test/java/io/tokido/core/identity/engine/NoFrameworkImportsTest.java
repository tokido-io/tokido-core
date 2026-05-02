package io.tokido.core.identity.engine;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Architecture gate: no class in this module may import Spring, Quarkus,
 * Jakarta, Servlet, or JAX-RS types. Identity modules are framework-agnostic
 * by ADR-0003.
 */
class NoFrameworkImportsTest {

    @Test
    void noFrameworkImports() {
        ArchRule rule = noClasses()
                .should().dependOnClassesThat().resideInAnyPackage(
                        "org.springframework..",
                        "io.quarkus..",
                        "jakarta..",
                        "javax.servlet..",
                        "jakarta.ws.rs..")
                .because("identity modules must remain framework-agnostic (ADR-0003)");

        rule.check(new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("io.tokido.core.identity.engine"));
    }
}
