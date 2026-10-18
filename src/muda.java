import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;

public class muda {
    public static String senha = "123456789";

    public static void main(String[] args) throws Exception {
        // gerar 20 bytes aleatorio para serem o segredo TOTP
        byte[] segredo = new byte[20];
        new SecureRandom().nextBytes(segredo);

        // codificando o segredo para Base32 usando biblioteca do enunciado
        Base32 b32 = new Base32(Base32.Alphabet.BASE32, false, false);
        String segredoBase32 = b32.toString(segredo);

        // chave AES derivada da senha pessoal
        SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
        prng.setSeed(senha.getBytes((StandardCharsets.UTF_8)));
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, prng);
        SecretKey chaveAes = kg.generateKey();

        // encriptar o segredo que está codificado em base32 usando a chave AES derivada da senha pessoal
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, chaveAes);
        byte[] segredoCifrado = aes.doFinal(segredoBase32.getBytes(StandardCharsets.UTF_8));

        System.out.println(segredoBase32);

        // descriptar
        Cipher dec = Cipher.getInstance("AES/ECB/PKCS5Padding");
        dec.init(Cipher.DECRYPT_MODE, chaveAes);
        String recuperado = new String(dec.doFinal(segredoCifrado), StandardCharsets.UTF_8);
        System.out.println("Ida e volta ok: " + recuperado.equals(segredoBase32));

        // gerar o codigo com a classe TOTP
        TOTP totp = new TOTP(recuperado, 30);
        while (true) {
            String codigo = totp.generateCode();
            System.out.println("Codigo agora: " + codigo);
            System.out.println("Valida: " + totp.validateCode(codigo));
            Thread.sleep(5000);
        }
    }
}
