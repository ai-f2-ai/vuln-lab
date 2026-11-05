// ATTENZIONE: applicazione volutamente vulnerabile, solo per collaudare scanner di sicurezza.
package lab.bank;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.logging.log4j.LogManager;
import org.springframework.web.bind.annotation.*;

@RestController
public class BankController {
    private static final String DB_URL = "jdbc:mysql://db:3306/bank";
    private static final String DB_PASS = "B4nk_Admin#2024";                 // VULN-J01
    private static final String AES_KEY = "0123456789abcdef";                 // VULN-J02 chiave fissa
    private static final String AWS_KEY = "AKIAV5HDQ2LMWE8XRT3B";             // VULN-J03

    @GetMapping("/account")
    public String account(@RequestParam String id) throws Exception {
        Connection c = DriverManager.getConnection(DB_URL, "root", DB_PASS);
        ResultSet rs = c.createStatement().executeQuery("SELECT * FROM accounts WHERE id=" + id); // VULN-J04 SQLi
        return rs.next() ? rs.getString(1) : "";
    }

    @GetMapping("/log")
    public String log(@RequestParam String msg) {
        LogManager.getLogger().error("Richiesta: " + msg);                    // VULN-J05 Log4Shell (dipendenza + uso)
        return "ok";
    }

    @GetMapping("/read")
    public String read(@RequestParam String f) throws IOException {
        return new String(java.nio.file.Files.readAllBytes(new File("/data/" + f).toPath())); // VULN-J06 path traversal
    }

    @PostMapping("/restore")
    public Object restore(@RequestBody byte[] body) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(body)).readObject();   // VULN-J07 deserializzazione
    }

    @PostMapping("/xml")
    public String xml(@RequestBody byte[] body) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new ByteArrayInputStream(body)).getDocumentElement().getNodeName();  // VULN-J08 XXE
    }

    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);                                       // VULN-J09 command injection
        return "ok";
    }

    @GetMapping("/hash")
    public byte[] hash(@RequestParam String p) throws Exception {
        return MessageDigest.getInstance("MD5").digest(p.getBytes());         // VULN-J10 MD5
    }

    @GetMapping("/enc")
    public byte[] enc(@RequestParam String p) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");                // VULN-J11 cifrario debole
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY.substring(0, 8).getBytes(), "DES"));
        return c.doFinal(p.getBytes());
    }

    @GetMapping("/otp")
    public int otp() { return new Random().nextInt(999999); }                 // VULN-J12 PRNG debole

    @GetMapping("/safe")
    public String safe(@RequestParam String id) throws Exception {             // NON vulnerabile
        Connection c = DriverManager.getConnection(DB_URL, "root", DB_PASS);
        PreparedStatement ps = c.prepareStatement("SELECT * FROM accounts WHERE id=?");
        ps.setString(1, id);
        return ps.executeQuery().next() ? "yes" : "no";
    }
}
