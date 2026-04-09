package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

/**
 * FreeIPA Certificate Enrollment Service for TAK Server.
 *
 * <h2>Purpose</h2>
 * Runs as a standalone process alongside TAK Server, replacing the built-in
 * certificate-enrollment service on port 8446.  ATAK clients enroll exactly
 * as normal – no client-side changes required.
 *
 * FreeIPA becomes the single PKI authority: it issues, tracks and revokes
 * client certificates.  Revocation is as simple as disabling the user in
 * the FreeIPA dashboard or running {@code ipa cert-revoke <serial>}.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>Starts an embedded HTTPS server on port 8446 (configurable).</li>
 *   <li>ATAK sends HTTP Basic Auth credentials to
 *       {@code POST /Marti/enrollment/enrollment}.</li>
 *   <li>Credentials are validated against FreeIPA.</li>
 *   <li>A fresh RSA key pair + PKCS#10 CSR are generated.</li>
 *   <li>The CSR is submitted to the FreeIPA {@code cert_request} API.</li>
 *   <li>The signed certificate and FreeIPA CA chain are packaged into a
 *       PKCS#12 bundle and returned to ATAK.</li>
 * </ol>
 *
 * <h2>LDAP integration</h2>
 * FreeIPA LDAP is already configured as TAK Server's auth provider.
 * Disabling a FreeIPA account immediately revokes LDAP access AND prevents
 * future certificate enrollments from that account.
 *
 * <h2>Deployment</h2>
 * <pre>
 * # Build (no credentials required)
 * mvn -f pom.xml package
 *
 * # Disable TAK Server's built-in 8446 connector in CoreConfig.xml first, then:
 * java -jar takserver-freeipa-cert-plugin-1.0.0.jar /opt/tak/conf/freeipa-enrollment.yaml
 *
 * # Or run as a systemd service – see deployment/freeipa-enrollment.service
 * </pre>
 */
public class FreeIPACertPlugin {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public static void main(String[] args) throws Exception {
        String configPath = args.length > 0
                ? args[0]
                : "/opt/tak/conf/plugins/tak.server.plugins.FreeIPACertPlugin.yaml";

        logger.info("=======================================================");
        logger.info("  FreeIPA Certificate Enrollment Service starting");
        logger.info("  Config: {}", configPath);
        logger.info("=======================================================");

        FreeIPAConfig cfg = FreeIPAConfig.fromYamlFile(configPath);
        FreeIPAApiClient apiClient = new FreeIPAApiClient(cfg);
        CertificateManager certMgr = new CertificateManager(cfg, apiClient);
        FreeIPAEnrollmentServer server = new FreeIPAEnrollmentServer(cfg, certMgr);

        server.start();

        logger.info("Enrollment endpoint: https://<host>:{}/Marti/enrollment/enrollment",
                cfg.getEnrollmentPort());
        logger.info("FreeIPA: {}  realm: {}", cfg.getFreeIpaUrl(), cfg.getFreeIpaRealm());
        logger.info("ATAK users enroll normally – no client changes required.");

        // Graceful shutdown on Ctrl-C / SIGTERM
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received – stopping...");
            server.stop();
            apiClient.close();
            logger.info("Stopped.");
        }));

        // Keep the main thread alive
        Thread.currentThread().join();
    }
}
