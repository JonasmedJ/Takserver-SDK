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
    private final String certPassword;
    private final String certOrganisation;
    private final String certCountry;
    private final int    rsaKeySize;

    private FreeIPAConfig(Builder b) {
        this.freeIpaUrl                = b.freeIpaUrl;
        this.freeIpaRealm              = b.freeIpaRealm;
        this.freeIpaAdminUser          = b.freeIpaAdminUser;
        this.freeIpaAdminPassword      = b.freeIpaAdminPassword;
        this.freeIpaCertProfile        = b.freeIpaCertProfile;
        this.freeIpaCaCn               = b.freeIpaCaCn;
        this.freeIpaTruststorePath     = b.freeIpaTruststorePath;
        this.freeIpaTruststorePassword = b.freeIpaTruststorePassword;
        this.skipFreeIpaTlsVerify      = b.skipFreeIpaTlsVerify;
        this.enrollmentPort            = b.enrollmentPort;
        this.keystorePath              = b.keystorePath;
        this.keystorePassword          = b.keystorePassword;
        this.certPassword              = b.certPassword;
        this.certOrganisation          = b.certOrganisation;
        this.certCountry               = b.certCountry;
        this.rsaKeySize                = b.rsaKeySize;
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
        String  certPassword              = "atakatak";
        String  certOrganisation          = "TAK";
        String  certCountry               = "US";
        int     rsaKeySize                = 2048;

        FreeIPAConfig build() { return new FreeIPAConfig(this); }
    }
}
