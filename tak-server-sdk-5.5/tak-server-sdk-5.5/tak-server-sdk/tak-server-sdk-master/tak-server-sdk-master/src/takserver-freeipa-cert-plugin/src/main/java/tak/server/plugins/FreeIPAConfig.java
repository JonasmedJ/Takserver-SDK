package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

/**
 * Configuration for the FreeIPA Certificate Enrollment Plugin.
 *
 * All values are read from the plugin YAML file located at:
 *   /opt/tak/conf/plugins/tak.server.plugins.FreeIPACertPlugin.yaml
 */
public class FreeIPAConfig {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    // ── FreeIPA server ──────────────────────────────────────────────────────
    /** Base URL of the FreeIPA server, e.g. https://ipa.example.com */
    private final String freeIpaUrl;

    /** Kerberos realm, e.g. EXAMPLE.COM  (must be uppercase) */
    private final String freeIpaRealm;

    /** FreeIPA admin account used by the plugin to issue certificates */
    private final String freeIpaAdminUser;

    /** Password for the FreeIPA admin account */
    private final String freeIpaAdminPassword;

    /** Certificate profile name in FreeIPA, e.g. caIPAserviceCert or IECUserRoles */
    private final String freeIpaCertProfile;

    /** CA sub-authority CN in FreeIPA – normally "ipa" */
    private final String freeIpaCaCn;

    // ── TLS trust for connections to FreeIPA ────────────────────────────────
    /**
     * Path to a PKCS12 trust-store containing the FreeIPA CA certificate.
     * Leave blank to rely on the JVM's default trust store.
     */
    private final String freeIpaTruststorePath;

    /** Password for the trust-store above */
    private final String freeIpaTruststorePassword;

    /**
     * Skip TLS certificate validation when calling the FreeIPA API.
     * Set to true only in isolated lab environments – never in production.
     */
    private final boolean skipFreeIpaTlsVerify;

    // ── Enrollment HTTPS server ─────────────────────────────────────────────
    /**
     * TCP port the plugin listens on for ATAK certificate-enrollment requests.
     *
     * TAK Server already occupies port 8446 for its built-in enrollment service.
     * Use 8447 (default) unless you have disabled that service and want to keep
     * the standard port number.
     */
    private final int enrollmentPort;

    /**
     * Path to the PKCS12 key-store that provides the TLS server identity for
     * the enrollment endpoint, e.g. /opt/tak/certs/server.p12
     */
    private final String keystorePath;

    /** Password for the key-store above */
    private final String keystorePassword;

    /**
     * Password embedded in the PKCS12 bundle that is delivered to ATAK clients.
     * Defaults to "atakatak" – the TAK ecosystem convention.
     */
    private final String certPassword;

    // ── Certificate subject metadata ────────────────────────────────────────
    /** Organisation field in the generated certificate subject (O=) */
    private final String certOrganisation;

    /** Country field in the generated certificate subject (C=) */
    private final String certCountry;

    /** RSA key size used when generating client key pairs (2048 or 4096) */
    private final int rsaKeySize;

    // ───────────────────────────────────────────────────────────────────────

    private FreeIPAConfig(Builder b) {
        this.freeIpaUrl               = b.freeIpaUrl;
        this.freeIpaRealm             = b.freeIpaRealm;
        this.freeIpaAdminUser         = b.freeIpaAdminUser;
        this.freeIpaAdminPassword     = b.freeIpaAdminPassword;
        this.freeIpaCertProfile       = b.freeIpaCertProfile;
        this.freeIpaCaCn              = b.freeIpaCaCn;
        this.freeIpaTruststorePath    = b.freeIpaTruststorePath;
        this.freeIpaTruststorePassword = b.freeIpaTruststorePassword;
        this.skipFreeIpaTlsVerify     = b.skipFreeIpaTlsVerify;
        this.enrollmentPort           = b.enrollmentPort;
        this.keystorePath             = b.keystorePath;
        this.keystorePassword         = b.keystorePassword;
        this.certPassword             = b.certPassword;
        this.certOrganisation         = b.certOrganisation;
        this.certCountry              = b.certCountry;
        this.rsaKeySize               = b.rsaKeySize;
    }

    /** Build a {@code FreeIPAConfig} from the TAK Server plugin configuration object. */
    public static FreeIPAConfig fromPluginConfig(PluginConfiguration cfg) {
        Builder b = new Builder();

        if (cfg.containsProperty("freeIpaUrl"))
            b.freeIpaUrl = (String) cfg.getProperty("freeIpaUrl");
        if (cfg.containsProperty("freeIpaRealm"))
            b.freeIpaRealm = ((String) cfg.getProperty("freeIpaRealm")).toUpperCase();
        if (cfg.containsProperty("freeIpaAdminUser"))
            b.freeIpaAdminUser = (String) cfg.getProperty("freeIpaAdminUser");
        if (cfg.containsProperty("freeIpaAdminPassword"))
            b.freeIpaAdminPassword = (String) cfg.getProperty("freeIpaAdminPassword");
        if (cfg.containsProperty("freeIpaCertProfile"))
            b.freeIpaCertProfile = (String) cfg.getProperty("freeIpaCertProfile");
        if (cfg.containsProperty("freeIpaCaCn"))
            b.freeIpaCaCn = (String) cfg.getProperty("freeIpaCaCn");
        if (cfg.containsProperty("freeIpaTruststorePath"))
            b.freeIpaTruststorePath = (String) cfg.getProperty("freeIpaTruststorePath");
        if (cfg.containsProperty("freeIpaTruststorePassword"))
            b.freeIpaTruststorePassword = (String) cfg.getProperty("freeIpaTruststorePassword");
        if (cfg.containsProperty("skipFreeIpaTlsVerify"))
            b.skipFreeIpaTlsVerify = Boolean.parseBoolean(
                    cfg.getProperty("skipFreeIpaTlsVerify").toString());
        if (cfg.containsProperty("enrollmentPort"))
            b.enrollmentPort = (Integer) cfg.getProperty("enrollmentPort");
        if (cfg.containsProperty("keystorePath"))
            b.keystorePath = (String) cfg.getProperty("keystorePath");
        if (cfg.containsProperty("keystorePassword"))
            b.keystorePassword = (String) cfg.getProperty("keystorePassword");
        if (cfg.containsProperty("certPassword"))
            b.certPassword = (String) cfg.getProperty("certPassword");
        if (cfg.containsProperty("certOrganisation"))
            b.certOrganisation = (String) cfg.getProperty("certOrganisation");
        if (cfg.containsProperty("certCountry"))
            b.certCountry = (String) cfg.getProperty("certCountry");
        if (cfg.containsProperty("rsaKeySize"))
            b.rsaKeySize = (Integer) cfg.getProperty("rsaKeySize");

        FreeIPAConfig config = b.build();
        config.validate();
        return config;
    }

    private void validate() {
        if (freeIpaUrl == null || freeIpaUrl.isBlank())
            throw new IllegalStateException("freeIpaUrl must be set in the plugin YAML");
        if (freeIpaRealm == null || freeIpaRealm.isBlank())
            throw new IllegalStateException("freeIpaRealm must be set in the plugin YAML");
        if (freeIpaAdminUser == null || freeIpaAdminUser.isBlank())
            throw new IllegalStateException("freeIpaAdminUser must be set in the plugin YAML");
        if (freeIpaAdminPassword == null || freeIpaAdminPassword.isBlank())
            throw new IllegalStateException("freeIpaAdminPassword must be set in the plugin YAML");
        if (keystorePath == null || keystorePath.isBlank())
            throw new IllegalStateException("keystorePath must be set – the enrollment endpoint requires TLS");
        logger.info("FreeIPAConfig validated: url={} realm={} port={} profile={}",
                freeIpaUrl, freeIpaRealm, enrollmentPort, freeIpaCertProfile);
    }

    // ── Getters ─────────────────────────────────────────────────────────────

    public String getFreeIpaUrl()               { return freeIpaUrl; }
    public String getFreeIpaRealm()             { return freeIpaRealm; }
    public String getFreeIpaAdminUser()         { return freeIpaAdminUser; }
    public String getFreeIpaAdminPassword()     { return freeIpaAdminPassword; }
    public String getFreeIpaCertProfile()       { return freeIpaCertProfile; }
    public String getFreeIpaCaCn()              { return freeIpaCaCn; }
    public String getFreeIpaTruststorePath()    { return freeIpaTruststorePath; }
    public String getFreeIpaTruststorePassword(){ return freeIpaTruststorePassword; }
    public boolean isSkipFreeIpaTlsVerify()     { return skipFreeIpaTlsVerify; }
    public int    getEnrollmentPort()           { return enrollmentPort; }
    public String getKeystorePath()             { return keystorePath; }
    public String getKeystorePassword()         { return keystorePassword; }
    public String getCertPassword()             { return certPassword; }
    public String getCertOrganisation()         { return certOrganisation; }
    public String getCertCountry()              { return certCountry; }
    public int    getRsaKeySize()               { return rsaKeySize; }

    // ── Builder ─────────────────────────────────────────────────────────────

    private static class Builder {
        String  freeIpaUrl               = null;
        String  freeIpaRealm             = null;
        String  freeIpaAdminUser         = "admin";
        String  freeIpaAdminPassword     = null;
        String  freeIpaCertProfile       = "caIPAserviceCert";
        String  freeIpaCaCn              = "ipa";
        String  freeIpaTruststorePath    = null;
        String  freeIpaTruststorePassword = "changeme";
        boolean skipFreeIpaTlsVerify     = false;
        int     enrollmentPort           = 8446;
        String  keystorePath             = null;
        String  keystorePassword         = "atakatak";
        String  certPassword             = "atakatak";
        String  certOrganisation         = "TAK";
        String  certCountry              = "US";
        int     rsaKeySize               = 2048;

        FreeIPAConfig build() { return new FreeIPAConfig(this); }
    }
}
