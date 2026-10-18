import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Abre um arquivo protegido da pasta segura: envelope -> semente -> chave AES
 * -> decriptacao do .enc -> verificacao da assinatura (.asd).
 * Serve para index, share e, depois, para os arquivos secretos.
 */
public class Desempacotador {

    /** Envelope, chave AES ou decriptacao falharam (problema de sigilo). */
    public static class FalhaDecriptacao extends Exception {
        public FalhaDecriptacao(String msg, Throwable causa) { super(msg, causa); }
    }

    /** Decriptou, mas a assinatura nao confere (integridade/autenticidade). */
    public static class FalhaVerificacao extends Exception {
        public FalhaVerificacao(String msg, Throwable causa) { super(msg, causa); }
    }

    // ---------- chaves e certificado ----------

    public static PrivateKey restaurarChavePrivada(byte[] arquivoChave, String frase) throws Exception {
        try {
            SecretKey chaveAes = derivarChaveAes(frase.getBytes(StandardCharsets.UTF_8));
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aes.init(Cipher.DECRYPT_MODE, chaveAes);
            byte[] decifrado = aes.doFinal(arquivoChave);

            String base64 = new String(decifrado, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] pkcs8 = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new Exception("Frase secreta invalida", e);
        }
    }

    public static X509Certificate lerCertificado(byte[] bytes) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
    }

    // ---------- etapas do pipeline ----------

    /** SHA1PRNG semeado com a semente + KeyGenerator de 256 bits. */
    public static SecretKey derivarChaveAes(byte[] semente) throws GeneralSecurityException {
        SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
        prng.setSeed(semente);                       // setSeed ANTES de gerar
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, prng);
        return kg.generateKey();
    }

    /** Abre o envelope digital (RSA/ECB/PKCS1) e devolve a semente. */
    public static byte[] abrirEnvelope(byte[] envelope, PrivateKey chavePrivada) throws GeneralSecurityException {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, chavePrivada);
        return rsa.doFinal(envelope);
    }

    public static byte[] decriptarAes(byte[] criptograma, SecretKey chave) throws GeneralSecurityException {
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, chave);
        return aes.doFinal(criptograma);
    }

    public static boolean verificarAssinatura(byte[] textoPlano, byte[] assinatura, PublicKey chavePublica)
            throws GeneralSecurityException {
        Signature v = Signature.getInstance("SHA1withRSA");
        v.initVerify(chavePublica);
        v.update(textoPlano);                        // assinatura e sobre o TEXTO PLANO
        return v.verify(assinatura);
    }

    // ---------- fluxo completo ----------

    /**
     * @param pasta              pasta segura
     * @param nomeCodigo         "index", "share" ou o nome codigo de um arquivo
     * @param sufixoEnvelope     "env" (dono) ou "ID.shr" (compartilhado, ex.: "1.shr")
     * @param chavePrivadaAbre   chave privada de quem abre o envelope
     * @param chavePublicaAssina chave publica de quem assinou (admin para index/share)
     */
    public static byte[] abrir(File pasta, String nomeCodigo, String sufixoEnvelope,
                               PrivateKey chavePrivadaAbre, PublicKey chavePublicaAssina)
            throws FalhaDecriptacao, FalhaVerificacao {

        if (!nomeCodigo.matches("[A-Za-z0-9]+")) {
            throw new FalhaDecriptacao("Nome codigo invalido: " + nomeCodigo, null);
        }

        byte[] textoPlano;
        try {
            byte[] envelope = Files.readAllBytes(new File(pasta, nomeCodigo + "." + sufixoEnvelope).toPath());
            byte[] enc = Files.readAllBytes(new File(pasta, nomeCodigo + ".enc").toPath());

            byte[] semente = abrirEnvelope(envelope, chavePrivadaAbre);
            SecretKey chaveAes = derivarChaveAes(semente);
            textoPlano = decriptarAes(enc, chaveAes);
        } catch (IOException | GeneralSecurityException e) {
            throw new FalhaDecriptacao("Falha na decriptacao de " + nomeCodigo, e);
        }

        try {
            byte[] asd = Files.readAllBytes(new File(pasta, nomeCodigo + ".asd").toPath());
            if (!verificarAssinatura(textoPlano, asd, chavePublicaAssina)) {
                throw new FalhaVerificacao("Assinatura nao confere para " + nomeCodigo, null);
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new FalhaVerificacao("Falha na verificacao de " + nomeCodigo, e);
        }

        return textoPlano;
    }
}