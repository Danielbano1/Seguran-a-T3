import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Uso: java DesempacotadorTeste <pasta segura> <chave privada admin> <certificado admin> <frase>
 * Ex.: java DesempacotadorTeste Files Keys/admin-pkcs8-aes.key Keys/admin-x509.crt admin
 * (ajuste os nomes dos arquivos conforme o pacote)
 */
public class DesempacotadorTeste {
    public static void main(String[] args) throws Exception {
        Object[] retorno = Main.chaves();
        PublicKey pub = (PublicKey) retorno[0];
        PrivateKey priv = (PrivateKey) retorno[1];
        File pasta = new File("resources/Pacote-T3/Files");

        String[] nomes = {"index", "share"};
        for (String nome : nomes) {
            System.out.println("\n===== " + nome + " =====");
            try {
                byte[] texto = Desempacotador.abrir(pasta, nome, "env", priv, pub);
                System.out.println("Decriptado e verificado com sucesso.");
                System.out.println(new String(texto, StandardCharsets.UTF_8));
            } catch (Desempacotador.FalhaDecriptacao e) {
                System.out.println("FALHA DE DECRIPTACAO: " + e.getMessage());
                if (e.getCause() != null) e.getCause().printStackTrace();
            } catch (Desempacotador.FalhaVerificacao e) {
                System.out.println("FALHA DE VERIFICACAO: " + e.getMessage());
                if (e.getCause() != null) e.getCause().printStackTrace();
            }
        }
    }
}