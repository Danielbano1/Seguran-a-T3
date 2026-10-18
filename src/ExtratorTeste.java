import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ExtratorTeste {
    public static void main(String[] args) throws Exception {
        Object[] retorno = Main.chaves();
        PublicKey pub = (PublicKey) retorno[0];
        PrivateKey priv = (PrivateKey) retorno[1];
        File pasta = new File("resources/Pacote-T3/Files");

        String nome = "XXYYZZ00";

        try {
            byte[] conteudo = Desempacotador.abrir(pasta, nome, "env", priv, pub);
            // logs 7018 e 7019
            File destino = new File("resources/Extraidos", "teste00.docx");
            Files.write(destino.toPath(), conteudo);
            // avisar sucesso com destino.getAbsolutePath()
            System.out.println(destino.getAbsolutePath());
        } catch (Desempacotador.FalhaDecriptacao e) {
            System.out.println("FALHA DE DECRIPTACAO: " + e.getMessage());
            if (e.getCause() != null) e.getCause().printStackTrace();
        } catch (Desempacotador.FalhaVerificacao e) {
            System.out.println("FALHA DE VERIFICACAO: " + e.getMessage());
            if (e.getCause() != null) e.getCause().printStackTrace();
        }
    }
}
