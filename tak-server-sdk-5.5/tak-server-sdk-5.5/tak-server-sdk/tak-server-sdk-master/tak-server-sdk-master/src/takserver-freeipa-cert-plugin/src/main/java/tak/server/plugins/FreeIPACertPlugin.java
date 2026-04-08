package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

/**
 * TAK Server plugin – FreeIPA Certificate Enrollment.
 *
 * <h2>Purpose</h2>
 * When an ATAK client requests a certificate (normally via port 8446 on TAK
 * Server), this plugin instead routes the request to a FreeIPA server.
 * FreeIPA becomes the single PKI authority: it issues, tracks, and revokes
 * client certificates.  Revocation is as simple as disabling the user account
 * or revoking the cert in the FreeIPA web dashboard.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>The plugin starts an embedded HTTPS server on the configured
 *       {@code enrollmentPort} (default 8447).  This port mirrors TAK Server's
 *       enrollment protocol, so ATAK clients need only point to this port
 *       instead of 8446.</li>
 *   <li>ATAK sends HTTP Basic Auth credentials to
 *       {@code POST /Marti/enrollment/enrollment}.</li>
 *   <li>The plugin validates the credentials against FreeIPA.</li>
 *   <li>A fresh RSA key pair + PKCS#10 CSR are generated for the user.</li>
 *   <li>The CSR is submitted to the FreeIPA {@code cert_request} API.</li>
 *   <li>The signed certificate and FreeIPA CA chain are packaged into a
 *       PKCS#12 bundle and returned to the ATAK client.</li>
 * </ol>
 *
 * <h2>LDAP integration</h2>
 * FreeIPA LDAP is expected to already be configured as TAK Server's auth
 * provider.  The same user account controls both TAK access (LDAP groups) and
 * certificate issuance.  Disabling or deleting the FreeIPA account immediately
 * revokes LDAP access AND prevents future certificate enrollments.
 *
 * <h2>Deployment</h2>
 * <ol>
 *   <li>Build: {@code ./gradlew :takserver-freeipa-cert-plugin:shadowJar}</li>
 *   <li>Copy the resulting JAR to {@code /opt/tak/lib/}.</li>
 *   <li>Edit {@code /opt/tak/conf/plugins/tak.server.plugins.FreeIPACertPlugin.yaml}
 *       with your FreeIPA details (auto-created on first run with defaults).</li>
 *   <li>Restart TAK Server: {@code sudo systemctl restart takserver}.</li>
 *   <li>Configure ATAK clients to enroll via
 *       {@code https://<server>:<enrollmentPort>}.</li>
 * </ol>
 *
 * <h2>Trust store for ATAK</h2>
 * After enrollment the returned PKCS#12 contains the FreeIPA CA as a trusted
 * certificate.  Import it into ATAK via the Import Manager.  Additionally,
 * add the FreeIPA CA to TAK Server's trust store so that TAK Server accepts
 * client certificates issued by FreeIPA for mTLS connections.
 */
@TakServerPlugin(
        name        = "FreeIPA Certificate Enrollment Plugin",
        description = "Routes ATAK certificate enrollment to FreeIPA for centralized PKI and revocation management")
public class FreeIPACertPlugin extends MessageSenderBase {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private FreeIPAEnrollmentServer enrollmentServer;
    private FreeIPAApiClient        apiClient;

    @Override
    public void start() {
        logger.info("╔══════════════════════════════════════════════════╗");
        logger.info("║   FreeIPA Certificate Enrollment Plugin starting  ║");
        logger.info("╚══════════════════════════════════════════════════╝");

        try {
            FreeIPAConfig cfg = FreeIPAConfig.fromPluginConfig(config);

            apiClient             = new FreeIPAApiClient(cfg);
            CertificateManager cm = new CertificateManager(cfg, apiClient);
            enrollmentServer      = new FreeIPAEnrollmentServer(cfg, cm);

            enrollmentServer.start();

            logger.info("Plugin started – enrollment endpoint: https://<host>:{}/Marti/enrollment/enrollment",
                    cfg.getEnrollmentPort());
            logger.info("FreeIPA server: {} realm: {}", cfg.getFreeIpaUrl(), cfg.getFreeIpaRealm());

        } catch (Exception e) {
            logger.error("Failed to start FreeIPA Certificate Enrollment Plugin – check YAML config", e);
        }
    }

    @Override
    public void stop() {
        logger.info("Stopping FreeIPA Certificate Enrollment Plugin...");
        if (enrollmentServer != null) {
            enrollmentServer.stop();
        }
        if (apiClient != null) {
            apiClient.close();
        }
        logger.info("FreeIPA Certificate Enrollment Plugin stopped");
    }
}
