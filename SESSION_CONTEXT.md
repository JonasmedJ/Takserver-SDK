# FreeIPA Certificate Enrollment Plugin — Session Context

> **Branch:** `claude/fix-atak-certificate-enrollment-CBoME`
> **Last updated:** 2026-04-23
> **Purpose:** Resume context for future sessions without re-reading the full transcript.

---

## 1. What This Plugin Does

A **standalone HTTPS service** (not an embedded TAK Server plugin) that replaces TAK Server's
built-in enrollment endpoint on port 8446. ATAK clients enroll exactly as they would against a
normal TAK Server — no client-side changes required.

**Endpoints exposed:**

| Path | Method | Purpose |
|---|---|---|
| `/Marti/enrollment/enrollment` | POST | Legacy PKCS#12 enrollment (Basic Auth) |
| `/Marti/api/tls/signClient/v2` | POST | CSR signing flow (ATAK/WinTAK standard) |
| `/Marti/api/tls/config` | GET | CSR config (org/country) |
| `/Marti/api/tls/profile/enrollment` | GET | Enrollment ZIP (truststore + prefs) |
| `/Marti/api/device/profile/connection` | GET | Reconnect profile ZIP |
| `/Marti/enrollment/health` | GET | Liveness probe |

**Source tree:**
```
src/takserver-freeipa-cert-plugin/src/main/java/tak/server/plugins/
  FreeIPACertPlugin.java          # entry point / lifecycle
  FreeIPAConfig.java              # YAML config loader (+ CoreConfig.xml fallbacks)
  CoreConfigReader.java           # NEW: reads /opt/tak/CoreConfig.xml
  FreeIPAEnrollmentServer.java    # HTTPS server + all handlers
  CertificateManager.java         # PKI operations (CSR, PKCS12, truststore)
  FreeIPAApiClient.java           # FreeIPA JSON-RPC client
```

**Deployed JAR:**
`src/takserver-freeipa-cert-plugin/takserver-freeipa-cert-plugin-1.0.0.jar`

---

## 2. YAML Configuration (`/opt/tak/conf/plugins/tak.server.plugins.FreeIPACertPlugin.yaml`)

```yaml
# ── FreeIPA connection ────────────────────────────────────────────────────────
freeIpaUrl:           https://ipa.example.com
freeIpaRealm:         EXAMPLE.COM           # auto-uppercased
freeIpaAdminUser:     admin
freeIpaAdminPassword: secret
freeIpaCertProfile:   userCert              # default
freeIpaCaCn:          ipa                   # default

# Optional: custom FreeIPA TLS trust
# freeIpaTruststorePath: /opt/tak/certs/files/freeipa-truststore.p12
# freeIpaTruststorePassword: changeme
# skipFreeIpaTlsVerify: false               # dev-only!

# ── Enrollment server TLS ─────────────────────────────────────────────────────
# If omitted, auto-read from /opt/tak/CoreConfig.xml (keystoreFile + keystorePass)
keystorePath:     /opt/tak/certs/files/takserver.jks   # JKS or PKCS12
keystorePassword: atakatak

# ── Certificate properties ────────────────────────────────────────────────────
certPassword:     atakatak
certOrganisation: TAK
certCountry:      US
rsaKeySize:       2048
enrollmentPort:   8446

# ── ATAK profile delivery ─────────────────────────────────────────────────────
# takServerHost: 10.10.215.240     # IP/hostname used in channel-enable pref
# enrollmentTruststorePath: ...    # optional pre-built PKCS12 truststore for ATAK

# ── TAK Server admin API ─────────────────────────────────────────────────────
# If omitted, takServerApiUrl is derived from CoreConfig.xml HTTPS connector port
# takServerApiUrl:     https://localhost:8443
takAdminCertPath:      /opt/tak/certs/files/webadmin.p12
takAdminCertPassword:  atakatak

# ── CoreConfig.xml auto-read ──────────────────────────────────────────────────
# coreConfigPath: /opt/tak/CoreConfig.xml   # default — omit to use default
```

**CoreConfig.xml auto-read behaviour** (new in latest commit):
- Reads `//network/connector[@_name='https']/@port` → fills `takServerApiUrl`
- Reads `//security/tls/@keystoreFile` + `@keystorePass` + `@keystore` → fills `keystorePath`/`keystorePassword`/keystore type (JKS or PKCS12)
- Only fills fields **not already set** in the YAML

---

## 3. FreeIPA LDAP Attributes Required

These custom LDAP attributes must be added to the FreeIPA schema and set on each user:

| LDAP attribute | TAK pref key | Example value |
|---|---|---|
| `takcallsign` | `locationCallsign` | `testuser` |
| `takcolor` | `locationTeam` | `Yellow` |
| `takrole` | `atakRoleType` | `HQ` |

Schema definition (add via `ipa-server-manage` or raw LDIF):
```ldif
attributeTypes: ( 1.3.6.1.4.1.XXXXX.1 NAME 'takcallsign' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.XXXXX.2 NAME 'takcolor'    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.XXXXX.3 NAME 'takrole'     SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
```

---

## 4. Channels / Groups — How It Works

### Client-side (prefs pushed in enrollment ZIP)
The enrollment profile ZIP (`prefs/user-profile.pref`) now contains entries in **both** namespaces
to support both ATAK (military) and ATAK-CIV (civilian):

```xml
<preferences>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="prefs_enable_channels" class="class java.lang.String">true</entry>
    <entry key="prefs_enable_channels_host-{takServerHost}" class="class java.lang.String">true</entry>
  </preference>
  <preference version="1" name="com.atakmap.app.civ_preferences">
    <!-- same entries — covers ATAK-CIV -->
  </preference>
</preferences>
```

> **Key fix from new SDK analysis:** the user's channel pref files use
> `com.atakmap.app.civ_preferences`, not `com.atakmap.app_preferences`.
> Now both are emitted in the same file.

### Server-side (TAK Server group registration)
After cert issuance, the plugin calls:
1. `POST https://localhost:8443/user-management/api/new-user`
   - Body: `{"username":"test1","password":"<random>","groupList":["ipausers","takusers"]}`
2. Falls back to `PUT /user-management/api/update-groups` if user already exists

Groups come from FreeIPA's `memberof_group` field (`user_show` with `no_members=false`).

> **Why needed:** `x509useGroupCache=true` in CoreConfig.xml is supposed to do LDAP group lookup
> automatically, but in testing it produced zero LDAP activity (cache warmed in 0 seconds = empty).
> Direct API registration is the reliable alternative.

---

## 5. TAK Server Device Profiles (admin-configured)

After cert issuance the enrollment ZIP also merges profiles from the TAK Server admin dashboard:
- Calls `GET https://localhost:8443/Marti/api/tls/profile/enrollment` with the admin cert
- Skips `MANIFEST/manifest.xml`, `certs/truststore-root.p12`, `prefs/user-profile.pref`
  (our versions take precedence)
- All other entries (extra `.pref` files etc.) are appended to the ZIP

---

## 6. Keystore Type Support

`loadKeyManager()` now auto-detects keystore type:
- Explicit hint from `config.getKeystoreType()` (set via CoreConfig or YAML)
- Falls back to file extension: `.jks` → JKS, everything else → PKCS12

---

## 7. Known Issues / Outstanding

| Issue | Status |
|---|---|
| `x509useGroupCache` LDAP not triggering | Worked around via User Management API |
| Channels appearing in ATAK | Fixed via dual-namespace pref + server-side group registration |
| TAK Server device profiles merged | Done |
| ATAK callsign/team/role delivered | Done |

---

## 8. Build Instructions

The root `build.gradle` uses `grgit` to find git info (needs repo at `src/..`). Use the
standalone build workaround:

```bash
# Copy sources to standalone build dir
cp src/takserver-freeipa-cert-plugin/src/main/java/tak/server/plugins/*.java \
   /tmp/freeipa-build/src/main/java/tak/server/plugins/

# Build
cd /tmp/freeipa-build
/path/to/gradlew shadowJar   # uses Gradle 8.5 + com.gradleup.shadow 8.3.0

# Copy JAR back
cp build/libs/takserver-freeipa-cert-plugin-1.0.0.jar \
   src/takserver-freeipa-cert-plugin/takserver-freeipa-cert-plugin-1.0.0.jar
```

The standalone `build.gradle` and `settings.gradle` are in `/tmp/freeipa-build/`.
Gradle wrapper has been updated to **8.5** (Java 21 compatible).
Shadow plugin updated to **`com.gradleup.shadow` 8.3.0**.

---

## 9. Deployment

```bash
# On TAK Server host
cp takserver-freeipa-cert-plugin-1.0.0.jar /opt/tak/lib/plugins/
cp tak.server.plugins.FreeIPACertPlugin.yaml /opt/tak/conf/plugins/
systemctl restart freeipa-enrollment
journalctl -u freeipa-enrollment -f
```

CoreConfig.xml: disable TAK Server's built-in 8446 connector before deploying.

---

## 10. Files Changed This Session (since branch creation)

- `FreeIPAEnrollmentServer.java` — all handler logic, pref format, channel prefs, device profile merge, user registration, dual-namespace prefs, JKS support, `buildAdminSslContext()`, `resolveKeystoreType()`, `buildPrefEntries()`
- `FreeIPAConfig.java` — new fields: `takServerHost`, `takServerApiUrl`, `takAdminCertPath`, `takAdminCertPassword`, `coreConfigPath`, `keystoreType`, `enrollmentTruststoreType`; CoreConfig fallback logic
- `CoreConfigReader.java` — **new file**; reads CoreConfig.xml via XPath
- `CertificateManager.java` — added `getUserGroups()` delegate
- `FreeIPAApiClient.java` — added `getUserGroups()` (reads `memberof_group`)
- `build.gradle` (plugin) — shadow plugin 8.3.0, Gradle 8.5
- `build.gradle` (root) — grgit made resilient with try/catch
- `gradle-wrapper.properties` — upgraded to Gradle 8.5
