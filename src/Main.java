import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {
    private String email;
    private String chave_publica;
    private String chave_privada;
    private Byte[] array = new Byte[10240];

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Digite a frase secreta do administrador: ");
        String frase_secreta = scanner.nextLine();
        try {
            PrivateKey chavePrivada = restaurarChavePrivada("resources/Pacote-T3/Keys/admin-pkcs8-aes.key", frase_secreta);
        }catch (Exception e){
            System.out.print("Erro");
        }

        try {
            X509Certificate certificado = extrairInfosCertificado("resources/Pacote-T3/Keys/admin-x509.crt");
            System.out.printf("Versão: %d\n", certificado.getVersion());
            System.out.printf("Série: %s\n", certificado.getSerialNumber().toString(16));
            System.out.printf("Validade: %s\n", certificado.getNotBefore().toString());
            System.out.printf("Tipo de Assinatura: %s\n", certificado.getSigAlgName());
            System.out.printf("Emissor: %s\n", certificado.getIssuerX500Principal().getName());
            System.out.printf("Sujeito: %s\n", certificado.getSubjectX500Principal().getName());
            String sujeito = certificado.getSubjectX500Principal().getName();
            // extração e decodificação do email do sujeito
            Map<String, String> oids = new HashMap<>();
            oids.put("1.2.840.113549.1.9.1", "EMAILADDRESS");
            String dn = certificado.getSubjectX500Principal().getName(X500Principal.RFC2253, oids);

            int ini = dn.indexOf("EMAILADDRESS=");
            if (ini < 0) throw new IllegalArgumentException("Certificado sem e-mail");
            ini += "EMAILADDRESS=".length();
            int fim = dn.indexOf(',', ini);
            String email = (fim < 0) ? dn.substring(ini) : dn.substring(ini, fim);

            System.out.printf("E-mail: %s\n", email);
            PublicKey chavePublica = certificado.getPublicKey();
        } catch (Exception e) {
            System.out.print("Erro2");
        }

    }


    // versao de recebe o path e abre o arquivo (teste)
    // obtem a chave privada asimetrica do usuario a partir da frase secreta
    private static PrivateKey restaurarChavePrivada(String path_chave_privada, String frase_secreta) throws Exception {
        // Derivar a chave AES (que será usada para abrir/decriptar o arquivo da chave secreta asimetrica do usuario) a partir da frase secreta

        //  pegando instancia de classe que gera numeros aleatorios utilizando o algoritmo SHA1PRNG
        SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
        // colocando como semente do gerador os bytes da frase privada
        prng.setSeed(frase_secreta.getBytes(StandardCharsets.UTF_8));
        // pegando instancia da classe que gera chave simetrica utilizando o algoritmo AES
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        // passando os parametros necessarios para o gerador de chave simetrica (o tamanho da chave 256 bytes e a função de gerar numeros aleatorios)
        kg.init(256, prng);
        // gerando a chave simetrica
        SecretKey chaveAes = kg.generateKey();

        // Decriptar/abrir o arquivo de chave asimetrica

        // pega o arquivo de chave secreta que está em bytes
        byte[] cifrado = Files.readAllBytes(Paths.get(path_chave_privada));
        // cria uma instancia da classe que encripta e decripta, passando o algoritmo AES/ECB/PKCS5Padding
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // passo os parametros necessarios para o (des/en)criptador, o modo decriptação e a chave simetrica que veio a partir da frase secreta
        aes.init(Cipher.DECRYPT_MODE, chaveAes);
        // desencripto os bytes da chave privada
        byte[] decifrado = aes.doFinal(cifrado);

        // converter os bytes da chave privada em texto, remover o cabeçalho e decodificar Base64

        // converto os bytes da chave privada em texto
        String pem = new String(decifrado, StandardCharsets.UTF_8);
        // remover o cabeçalho e quebras de linha
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        // tirando a codificaçao base64 e mantendo a chave privada no padrão pkcs8 ainda em bytes
        byte[] pkcs8 = Base64.getDecoder().decode(base64);

        // Gerar a chave privada

        // etiqueta os bytes como padrao PKCS8
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        // gera a chave asimetrica privada
        PrivateKey chave_privada = KeyFactory.getInstance("RSA").generatePrivate(spec);

        return chave_privada;
    }

    // versao que recebe os bytes
    private PrivateKey restaurarChavePrivada(byte[] arquivo_chave_privada, String frase_secreta) throws Exception {
        // Derivar a chave AES (que será usada para abrir/decriptar o arquivo da chave secreta asimetrica do usuario) a partir da frase secreta

        //  pegando instancia de classe que gera numeros aleatorios utilizando o algoritmo SHA1PRNG
        SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
        // colocando como semente do gerador os bytes da frase privada
        prng.setSeed(frase_secreta.getBytes(StandardCharsets.UTF_8));
        // pegando instancia da classe que gera chave simetrica utilizando o algoritmo AES
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        // passando os parametros necessarios para o gerador de chave simetrica (o tamanho da chave 256 bytes e a função de gerar numeros aleatorios)
        kg.init(256, prng);
        // gerando a chave simetrica
        SecretKey chaveAes = kg.generateKey();

        // Decriptar/abrir o arquivo de chave asimetrica

        // cria uma instancia da classe que encripta e decripta, passando o algoritmo AES/ECB/PKCS5Padding
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // passo os parametros necessarios para o (des/en)criptador, o modo decriptação e a chave simetrica que veio a partir da frase secreta
        aes.init(Cipher.DECRYPT_MODE, chaveAes);
        // desencripto os bytes da chave privada
        byte[] decifrado = aes.doFinal(arquivo_chave_privada);

        // converter os bytes da chave privada em texto, remover o cabeçalho e decodificar Base64

        // converto os bytes da chave privada em texto
        String pem = new String(decifrado, StandardCharsets.UTF_8);
        // remover o cabeçalho e quebras de linha
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\\s", "");
        // tirando a codificaçao base64 e mantendo a chave privada no padrão pkcs8 ainda em bytes
        byte[] pkcs8 = Base64.getDecoder().decode(base64);

        // Gerar a chave privada

        // etiqueta os bytes como padrao PKCS8
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        // gera a chave asimetrica privada
        PrivateKey chave_privada = KeyFactory.getInstance("RSA").generatePrivate(spec);

        return chave_privada;
    }

    // versao de recebe o path e abre o arquivo (teste)
    private static X509Certificate extrairInfosCertificado(String path_certificado) throws Exception {
        // pega o arquivo de certificado e le seus bytes
        byte[] arquivoCertificado = Files.readAllBytes(Paths.get(path_certificado));

        // cria instancia da classe para gerar certificado
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // gerar certificado e fazer cast para X509Certificate
        X509Certificate certificado = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(arquivoCertificado));

        return certificado;
    }

    private static X509Certificate extrairInfosCertificado(byte[] arquivoCertificado) throws Exception {
        // cria instancia da classe para gerar certificado
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // gerar certificado e fazer cast para X509Certificate
        X509Certificate certificado = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(arquivoCertificado));

        return certificado;
    }


    private void gera_array(Byte[] array) {

    }

    private void assinar(String chave_privada, Byte[] array) {

    }

    private void verificar_assinatura(Byte[] array, String chave_publica) {

    }

}

// a partir da frase secreta conseguir a chave privada
// criar um array de byte de tamanho 10240
// assinar o array com a chave privada
// conferir assinatura com a chave publica