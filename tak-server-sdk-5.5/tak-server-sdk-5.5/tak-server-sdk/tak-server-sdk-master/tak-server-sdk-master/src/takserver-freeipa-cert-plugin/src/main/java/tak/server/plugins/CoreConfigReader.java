package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.lang.invoke.MethodHandles;

/**
 * Reads TAK Server's {@code CoreConfig.xml} and exposes the settings that are
 * useful as automatic fallbacks for the FreeIPA enrollment plugin.
 *
 * <p>All extracted values are available as plain public fields after a
 * successful {@link #read()} call.  Fields remain {@code null} or empty when
 * the corresponding element / attribute is absent from the XML.
 *
 * <p>Relative keystore / truststore paths are resolved against {@code /opt/tak/}
 * which is TAK Server's standard installation root.
 */
public class CoreConfigReader {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String DEFAULT_PATH = "/opt/tak/CoreConfig.xml";
    private static final String TAK_BASE = "/opt/tak/";

    private final String path;

    // ── Extracted fields ──────────────────────────────────────────────────────
    /** {@code https://localhost:<port>} derived from the HTTPS connector entry. */
    public String  httpsApiUrl;
    /** Absolute path to the TAK Server TLS keystore (may be JKS or PKCS12). */
    public String  keystoreFile;
    /** Password for {@link #keystoreFile}. */
    public String  keystorePass;
    /** Keystore type string from CoreConfig: {@code "JKS"} or {@code "PKCS12"}. */
    public String  keystoreType;
    /** Absolute path to the TAK Server TLS truststore. */
    public String  truststoreFile;
    /** Password for {@link #truststoreFile}. */
    public String  truststorePass;
    /** Truststore type string from CoreConfig: {@code "JKS"} or {@code "PKCS12"}. */
    public String  truststoreType;

    public CoreConfigReader(String path) {
        this.path = (path != null && !path.isBlank()) ? path : DEFAULT_PATH;
    }

    /**
     * Parse the CoreConfig.xml file and populate public fields.
     *
     * @return {@code true} if the file was found and parsed without errors;
     *         {@code false} if the file is absent or unreadable (non-fatal)
     */
    public boolean read() {
        File f = new File(path);
        if (!f.exists()) {
            logger.debug("CoreConfig.xml not found at {} – skipping TAK Server auto-config", path);
            return false;
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Harden against XXE attacks when processing the config file
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            Document doc = dbf.newDocumentBuilder().parse(f);
            doc.getDocumentElement().normalize();
            XPath xp = XPathFactory.newInstance().newXPath();

            // ── HTTPS connector → admin API URL ──────────────────────────────
            String port = xp.evaluate("//network/connector[@_name='https']/@port", doc).trim();
            if (port.isEmpty()) {
                // fall back: any connector on the standard 8443 port
                port = xp.evaluate("//network/connector[@port='8443']/@port", doc).trim();
            }
            if (!port.isEmpty()) {
                httpsApiUrl = "https://localhost:" + port;
                logger.info("CoreConfig: HTTPS port {} → takServerApiUrl={}", port, httpsApiUrl);
            }

            // ── TLS keystore ──────────────────────────────────────────────────
            keystoreFile = resolve(xp.evaluate("//security/tls/@keystoreFile", doc).trim());
            keystorePass = xp.evaluate("//security/tls/@keystorePass", doc).trim();
            keystoreType = xp.evaluate("//security/tls/@keystore",     doc).trim();

            // ── TLS truststore ────────────────────────────────────────────────
            truststoreFile = resolve(xp.evaluate("//security/tls/@truststoreFile", doc).trim());
            truststorePass = xp.evaluate("//security/tls/@truststorePass", doc).trim();
            truststoreType = xp.evaluate("//security/tls/@truststore",     doc).trim();

            if (!keystoreFile.isEmpty())
                logger.info("CoreConfig: TLS keystore={} type={}", keystoreFile, keystoreType);
            if (!truststoreFile.isEmpty())
                logger.info("CoreConfig: TLS truststore={} type={}", truststoreFile, truststoreType);

            return true;
        } catch (Exception e) {
            logger.warn("Could not read CoreConfig.xml from {}: {}", path, e.getMessage());
            return false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String resolve(String p) {
        if (p == null || p.isEmpty()) return "";
        return p.startsWith("/") ? p : TAK_BASE + p;
    }
}
