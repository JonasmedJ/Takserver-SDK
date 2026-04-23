package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.util.Collections;
import java.util.Map;

/**
 * Configuration for the FreeIPA Certificate Enrollment Service.
 *
 * Values are read from a YAML file (default location:
 * /opt/tak/conf/plugins/tak.server.plugins.FreeIPACertPlugin.yaml).
 * Pass a different path as the first CLI argument when starting the JAR.
 */
public class FreeIPAConfig {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final String freeIpaUrl;
    private final String freeIpaRealm;
    private final String freeIpaAdminUser;
    private final String freeIpaAdminPassword;
    private final String freeIpaCertProfile;
    private final String freeIpaCaCn;
    private final String freeIpaTruststorePath;
    private final String freeIpaTruststorePassword;
    private final boolean skipFreeIpaTlsVerify;
    private final int    enrollmentPort;
    private final String keystorePath;
    private final String keystorePassword;
    /** Keystore type: {@code "JKS"} or {@code "PKCS12"} (auto-detected or from CoreConfig). */
    private final String keystoreType;
    private final String certPassword;
    private final String certOrganisation;
    private final String certCountry;
    private final int    rsaKeySize;
    /**
     * Optional path to a pre-built PKCS12 truststore to deliver in the
     * {@code GET /Marti/api/tls/profile/enrollment} data package.
     * When {@code null} or blank the truststore is built dynamically from
     * the FreeIPA CA chain at request time.
     */
    private final String enrollmentTruststorePath;
    /** Password for {@link #enrollmentTruststorePath}. Defaults to "atakatak". */
    private final String enrollmentTruststorePassword;
    /** Truststore type: {@code "JKS"} or {@code "PKCS12"} (auto-detected or from CoreConfig). */
    private final String enrollmentTruststoreType;
    /**
     * IP address or hostname of the TAK Server as ATAK clients connect to it
     * (e.g. "10.10.215.240" or "tak.example.com").  Used to inject the
     * per-server channel-enable preference {@code prefs_enable_channels_host-<host>=true}
     * into the enrollment profile so ATAK shows channels immediately after enrollment.
     * Optional — if omitted, channels are enabled globally but not per-host.
     */
    private final String takServerHost;
    /** Base URL of the TAK Server admin API. Defaults to https://localhost:8443. */
    private final String takServerApiUrl;
    /**
     * Path to TAK Server's {@code CoreConfig.xml}.  When set (and the file exists)
     * the plugin reads it on startup and uses its TLS keystore / truststore paths
     * and HTTPS connector port as fallbacks for any YAML values not explicitly set.
     * Defaults to {@code /opt/tak/CoreConfig.xml}.
     */
    private final String coreConfigPath;
    /**
     * Path to a PKCS#12 certificate that has ROLE_ADMIN on the TAK Server
     * (e.g. /opt/tak/certs/files/webadmin.p12).  Used to call the TAK Server
     * profile API and merge admin-configured enrollment profiles into the ZIP.
     * Optional — if omitted, admin profiles are not merged.
     */
    private final String takAdminCertPath;
    /** Password for {@link #takAdminCertPath}. Defaults to "atakatak". */
    private final String takAdminCertPassword;

    private FreeIPAConfig(Builder b) {
        this.freeIpaUrl                    = b.freeIpaUrl;
        this.freeIpaRealm                  = b.freeIpaRealm;
        this.freeIpaAdminUser              = b.freeIpaAdminUser;
        this.freeIpaAdminPassword          = b.freeIpaAdminPassword;
        this.freeIpaCertProfile            = b.freeIpaCertProfile;
        this.freeIpaCaCn                   = b.freeIpaCaCn;
        this.freeIpaTruststorePath         = b.freeIpaTruststorePath;
        this.freeIpaTruststorePassword     = b.freeIpaTruststorePassword;
        this.skipFreeIpaTlsVerify          = b.skipFreeIpaTlsVerify;
        this.enrollmentPort                = b.enrollmentPort;
        this.keystorePath                  = b.keystorePath;
        this.keystorePassword              = b.keystorePassword;
        this.keystoreType                  = b.keystoreType;
        this.certPassword                  = b.certPassword;
        this.certOrganisation              = b.certOrganisation;
        this.certCountry                   = b.certCountry;
        this.rsaKeySize                    = b.rsaKeySize;
        this.enrollmentTruststorePath      = b.enrollmentTruststorePath;
        this.enrollmentTruststorePassword  = b.enrollmentTruststorePassword;
        this.enrollmentTruststoreType      = b.enrollmentTruststoreType;
        this.takServerHost                 = b.takServerHost;
        this.takServerApiUrl               = b.takServerApiUrl;
        this.takAdminCertPath              = b.takAdminCertPath;
        this.takAdminCertPassword          = b.takAdminCertPassword;
        this.coreConfigPath                = b.coreConfigPath;
    }

    /** Load configuration from a YAML file on disk. */
    @SuppressWarnings("unchecked")
    public static FreeIPAConfig fromYamlFile(String configPath) throws Exception {
        Map<String, Object> data = Collections.emptyMap();

        File f = new File(configPath);
        if (f.exists()) {
            Yaml yaml = new Yaml();
            try (InputStream is = new FileInputStream(f)) {
                Map<String, Object> loaded = yaml.load(is);
                if (loaded != null) data = loaded;
            }
            logger.info("Loaded config from {}", configPath);
        } else {
            logger.warn("Config file not found at {} – using built-in defaults. "
                    + "Copy the sample YAML and edit it before running in production.", configPath);
        }

        Builder b = new Builder();

        if (data.containsKey("freeIpaUrl"))
            b.freeIpaUrl = (String) data.get("freeIpaUrl");
        if (data.containsKey("freeIpaRealm"))
            b.freeIpaRealm = ((String) data.get("freeIpaRealm")).toUpperCase();
        if (data.containsKey("freeIpaAdminUser"))
            b.freeIpaAdminUser = (String) data.get("freeIpaAdminUser");
        if (data.containsKey("freeIpaAdminPassword"))
            b.freeIpaAdminPassword = (String) data.get("freeIpaAdminPassword");
        if (data.containsKey("freeIpaCertProfile"))
            b.freeIpaCertProfile = (String) data.get("freeIpaCertProfile");
        if (data.containsKey("freeIpaCaCn"))
            b.freeIpaCaCn = (String) data.get("freeIpaCaCn");
        if (data.containsKey("freeIpaTruststorePath"))
            b.freeIpaTruststorePath = (String) data.get("freeIpaTruststorePath");
        if (data.containsKey("freeIpaTruststorePassword"))
            b.freeIpaTruststorePassword = (String) data.get("freeIpaTruststorePassword");
        if (data.containsKey("skipFreeIpaTlsVerify"))
            b.skipFreeIpaTlsVerify = Boolean.parseBoolean(data.get("skipFreeIpaTlsVerify").toString());
        if (data.containsKey("enrollmentPort"))
            b.enrollmentPort = (Integer) data.get("enrollmentPort");
        if (data.containsKey("keystorePath"))
            b.keystorePath = (String) data.get("keystorePath");
        if (data.containsKey("keystorePassword"))
            b.keystorePassword = (String) data.get("keystorePassword");
        if (data.containsKey("certPassword"))
            b.certPassword = (String) data.get("certPassword");
        if (data.containsKey("certOrganisation"))
            b.certOrganisation = (String) data.get("certOrganisation");
        if (data.containsKey("certCountry"))
            b.certCountry = (String) data.get("certCountry");
        if (data.containsKey("rsaKeySize"))
            b.rsaKeySize = (Integer) data.get("rsaKeySize");
        if (data.containsKey("enrollmentTruststorePath"))
            b.enrollmentTruststorePath = (String) data.get("enrollmentTruststorePath");
        if (data.containsKey("enrollmentTruststorePassword"))
            b.enrollmentTruststorePassword = (String) data.get("enrollmentTruststorePassword");
        if (data.containsKey("takServerHost"))
            b.takServerHost = (String) data.get("takServerHost");
        if (data.containsKey("takServerApiUrl"))
            b.takServerApiUrl = (String) data.get("takServerApiUrl");
        if (data.containsKey("takAdminCertPath"))
            b.takAdminCertPath = (String) data.get("takAdminCertPath");
        if (data.containsKey("takAdminCertPassword"))
            b.takAdminCertPassword = (String) data.get("takAdminCertPassword");
        if (data.containsKey("coreConfigPath"))
            b.coreConfigPath = (String) data.get("coreConfigPath");

        // Apply CoreConfig.xml values as fallbacks for any YAML fields not set.
        // Only the HTTPS port and TLS keystore are safe to auto-read; the CoreConfig
        // truststore holds client-CA trust material, not the server CA ATAK needs.
        CoreConfigReader cc = new CoreConfigReader(b.coreConfigPath);
        if (cc.read()) {
            // Admin API URL: derive from HTTPS connector port
            if (!data.containsKey("takServerApiUrl") && cc.httpsApiUrl != null) {
                b.takServerApiUrl = cc.httpsApiUrl;
            }
            // TLS keystore for the enrollment endpoint (may be JKS or PKCS12)
            if (!data.containsKey("keystorePath")
                    && cc.keystoreFile != null && !cc.keystoreFile.isEmpty()) {
                b.keystorePath = cc.keystoreFile;
                b.keystoreType = cc.keystoreType;
                logger.info("Auto-configured keystorePath from CoreConfig: {}", cc.keystoreFile);
            }
            if (!data.containsKey("keystorePassword")
                    && cc.keystorePass != null && !cc.keystorePass.isEmpty()) {
                b.keystorePassword = cc.keystorePass;
            }
        }

        FreeIPAConfig config = b.build();
        config.validate();
        return config;
    }

    private void validate() {
        if (freeIpaUrl == null || freeIpaUrl.isBlank())
            throw new IllegalStateException("freeIpaUrl must be set in the YAML config");
        if (freeIpaRealm == null || freeIpaRealm.isBlank())
            throw new IllegalStateException("freeIpaRealm must be set in the YAML config");
        if (freeIpaAdminUser == null || freeIpaAdminUser.isBlank())
            throw new IllegalStateException("freeIpaAdminUser must be set in the YAML config");
        if (freeIpaAdminPassword == null || freeIpaAdminPassword.isBlank())
            throw new IllegalStateException("freeIpaAdminPassword must be set in the YAML config");
        if (keystorePath == null || keystorePath.isBlank())
            throw new IllegalStateException("keystorePath must be set – TLS is required on the enrollment endpoint");
        logger.info("Config OK – FreeIPA: {}  realm: {}  port: {}  profile: {}",
                freeIpaUrl, freeIpaRealm, enrollmentPort, freeIpaCertProfile);
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    public String  getFreeIpaUrl()                { return freeIpaUrl; }
    public String  getFreeIpaRealm()              { return freeIpaRealm; }
    public String  getFreeIpaAdminUser()          { return freeIpaAdminUser; }
    public String  getFreeIpaAdminPassword()      { return freeIpaAdminPassword; }
    public String  getFreeIpaCertProfile()        { return freeIpaCertProfile; }
    public String  getFreeIpaCaCn()               { return freeIpaCaCn; }
    public String  getFreeIpaTruststorePath()     { return freeIpaTruststorePath; }
    public String  getFreeIpaTruststorePassword() { return freeIpaTruststorePassword; }
    public boolean isSkipFreeIpaTlsVerify()       { return skipFreeIpaTlsVerify; }
    public int     getEnrollmentPort()            { return enrollmentPort; }
    public String  getKeystorePath()              { return keystorePath; }
    public String  getKeystorePassword()          { return keystorePassword; }
    public String  getCertPassword()              { return certPassword; }
    public String  getCertOrganisation()          { return certOrganisation; }
    public String  getCertCountry()               { return certCountry; }
    public int     getRsaKeySize()                { return rsaKeySize; }
    public String  getEnrollmentTruststorePath()     { return enrollmentTruststorePath; }
    public String  getEnrollmentTruststorePassword() { return enrollmentTruststorePassword; }
    public String  getTakServerHost()                { return takServerHost; }
    public String  getTakServerApiUrl()              { return takServerApiUrl; }
    public String  getTakAdminCertPath()             { return takAdminCertPath; }
    public String  getTakAdminCertPassword()         { return takAdminCertPassword; }
    public String  getCoreConfigPath()               { return coreConfigPath; }
    public String  getKeystoreType()                 { return keystoreType; }
    public String  getEnrollmentTruststoreType()     { return enrollmentTruststoreType; }

    // ── Builder ───────────────────────────────────────────────────────────────

    private static class Builder {
        String  freeIpaUrl                = null;
        String  freeIpaRealm              = null;
        String  freeIpaAdminUser          = "admin";
        String  freeIpaAdminPassword      = null;
        String  freeIpaCertProfile        = "userCert";
        String  freeIpaCaCn               = "ipa";
        String  freeIpaTruststorePath     = null;
        String  freeIpaTruststorePassword = "changeme";
        boolean skipFreeIpaTlsVerify      = false;
        int     enrollmentPort            = 8446;
        String  keystorePath              = null;
        String  keystorePassword          = "atakatak";
        String  keystoreType              = "PKCS12";
        String  certPassword              = "atakatak";
        String  certOrganisation          = "TAK";
        String  certCountry               = "US";
        int     rsaKeySize                = 2048;
        String  enrollmentTruststorePath     = null;
        String  enrollmentTruststorePassword = "atakatak";
        String  enrollmentTruststoreType     = "PKCS12";
        String  takServerHost                = null;
        String  takServerApiUrl              = "https://localhost:8443";
        String  takAdminCertPath             = null;
        String  takAdminCertPassword         = "atakatak";
        String  coreConfigPath               = CoreConfigReader.DEFAULT_PATH;

        FreeIPAConfig build() { return new FreeIPAConfig(this); }
    }
}
