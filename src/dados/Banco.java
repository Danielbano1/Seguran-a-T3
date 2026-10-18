package dados;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Acesso ao SQLite: cria o banco do zero (tabelas + carga de Grupos e Mensagens).
 * Cada chamada a conectar() abre uma conexao nova, com chaves estrangeiras ligadas.
 */
public class Banco {

    // O logView precisa abrir o MESMO arquivo: documente no README.
    private static String caminho = "cofre.db";

    public static void setCaminho(String novoCaminho) { caminho = novoCaminho; }

    public static Connection conectar() throws SQLException {
        Connection c = DriverManager.getConnection("jdbc:sqlite:" + caminho);
        try (Statement st = c.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");   // desligado por padrao no SQLite
        }
        return c;
    }

    /** Cria as tabelas (se nao existirem) e carrega Grupos e Mensagens. */
    public static void inicializar() throws SQLException {
        try (Connection c = conectar()) {
            c.setAutoCommit(false);
            try (Statement st = c.createStatement()) {

                st.execute("CREATE TABLE IF NOT EXISTS Grupos ("
                        + " GID  INTEGER PRIMARY KEY,"
                        + " NOME TEXT NOT NULL UNIQUE)");

                // Usuarios.KID referencia Chaveiro e Chaveiro.UID referencia Usuarios
                // (dependencia circular). No SQLite isso e aceito na criacao; na
                // insercao, grave o usuario com KID nulo, depois o Chaveiro, depois
                // atualize o KID (tudo na mesma transacao).
                st.execute("CREATE TABLE IF NOT EXISTS Usuarios ("
                        + " UID             INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + " LOGIN           TEXT    NOT NULL UNIQUE,"
                        + " NOME            TEXT    NOT NULL,"
                        + " GID             INTEGER NOT NULL REFERENCES Grupos(GID),"
                        + " KID             INTEGER REFERENCES Chaveiro(KID),"
                        + " SENHA_HASH      TEXT    NOT NULL,"       // bcrypt, 60 caracteres
                        + " TOTP_CIFRADO    BLOB    NOT NULL,"       // BASE32 cifrado com AES
                        + " TOTAL_ACESSOS   INTEGER NOT NULL DEFAULT 0,"
                        + " TOTAL_CONSULTAS INTEGER NOT NULL DEFAULT 0,"
                        + " ERROS_SENHA     INTEGER NOT NULL DEFAULT 0,"
                        + " ERROS_TOKEN     INTEGER NOT NULL DEFAULT 0,"
                        + " BLOQUEADO_ATE   INTEGER NOT NULL DEFAULT 0)"); // epoch em ms

                st.execute("CREATE TABLE IF NOT EXISTS Chaveiro ("
                        + " KID             INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + " UID             INTEGER NOT NULL REFERENCES Usuarios(UID),"
                        + " CERTIFICADO_PEM TEXT    NOT NULL,"
                        + " CHAVE_PRIVADA   BLOB    NOT NULL)");     // ja criptografada (.key)

                st.execute("CREATE TABLE IF NOT EXISTS Mensagens ("
                        + " MID   INTEGER PRIMARY KEY,"
                        + " TEXTO TEXT NOT NULL)");

                // Registros guarda so o MID (nunca o texto da mensagem).
                // LOGIN guarda o login digitado quando nao existe UID (mensagem 2005).
                st.execute("CREATE TABLE IF NOT EXISTS Registros ("
                        + " RID       INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + " DATA_HORA INTEGER NOT NULL,"             // epoch em ms
                        + " MID       INTEGER NOT NULL REFERENCES Mensagens(MID),"
                        + " UID       INTEGER REFERENCES Usuarios(UID),"
                        + " LOGIN     TEXT,"
                        + " ARQUIVO   TEXT)");
            }

            carregarGrupos(c);
            carregarMensagens(c);
            c.commit();
        }
    }

    /** true se ainda nao ha nenhum usuario: primeira partida (cadastro do admin). */
    public static boolean semUsuarios() throws SQLException {
        try (Connection c = conectar();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM Usuarios")) {
            return rs.next() && rs.getInt(1) == 0;
        }
    }

    // ---------- carga inicial ----------

    private static void carregarGrupos(Connection c) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT OR IGNORE INTO Grupos (GID, NOME) VALUES (?, ?)")) {
            ps.setInt(1, 1); ps.setString(2, "Administrador"); ps.executeUpdate();
            ps.setInt(1, 2); ps.setString(2, "Usuário");       ps.executeUpdate();
        }
    }

    private static final Object[][] MENSAGENS = {
            {1001, "Sistema iniciado."},
            {1002, "Sistema encerrado."},
            {1003, "Sessão iniciada para <login_name>."},
            {1004, "Sessão encerrada para <login_name>."},
            {1005, "Partida do sistema iniciada para cadastro do administrador."},
            {1006, "Partida do sistema iniciada para operação normal pelos usuários."},
            {2001, "Autenticação etapa 1 iniciada."},
            {2002, "Autenticação etapa 1 encerrada."},
            {2003, "Login name <login_name> identificado com acesso liberado."},
            {2004, "Login name <login_name> identificado com acesso bloqueado."},
            {2005, "Login name <login_name> não identificado."},
            {3001, "Autenticação etapa 2 iniciada para <login_name>."},
            {3002, "Autenticação etapa 2 encerrada para <login_name>."},
            {3003, "Senha pessoal verificada positivamente para <login_name>."},
            {3004, "Primeiro erro da senha pessoal contabilizado para <login_name>."},
            {3005, "Segundo erro da senha pessoal contabilizado para <login_name>."},
            {3006, "Terceiro erro da senha pessoal contabilizado para <login_name>."},
            {3007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 2."},
            {4001, "Autenticação etapa 3 iniciada para <login_name>."},
            {4002, "Autenticação etapa 3 encerrada para <login_name>."},
            {4003, "Token verificado positivamente para <login_name>."},
            {4004, "Primeiro erro de token contabilizado para <login_name>."},
            {4005, "Segundo erro de token contabilizado para <login_name>."},
            {4006, "Terceiro erro de token contabilizado para <login_name>."},
            {4007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 3."},
            {5001, "Tela principal apresentada para <login_name>."},
            {5002, "Opção 1 do menu principal selecionada por <login_name>."},
            {5003, "Opção 2 do menu principal selecionada por <login_name>."},
            {5004, "Opção 3 do menu principal selecionada por <login_name>."},
            {6001, "Tela de cadastro apresentada para <login_name>."},
            {6002, "Botão cadastrar pressionado por <login_name>."},
            {6003, "Senha pessoal inválida fornecida por <login_name>."},
            {6004, "Caminho do certificado digital inválido fornecido por <login_name>."},
            {6005, "Chave privada verificada negativamente para <login_name> (caminho inválido)."},
            {6006, "Chave privada verificada negativamente para <login_name> (frase secreta inválida)."},
            {6007, "Chave privada verificada negativamente para <login_name> (assinatura digital inválida)."},
            {6008, "Confirmação de dados aceita por <login_name>."},
            {6009, "Confirmação de dados rejeitada por <login_name>."},
            {6010, "Botão voltar de cadastro para o menu principal pressionado por <login_name>."},
            {7001, "Tela de consulta de arquivos secretos apresentada para <login_name>."},
            {7002, "Botão voltar de consulta para o menu principal pressionado por <login_name>."},
            {7003, "Botão Listar de consulta pressionado por <login_name>."},
            {7004, "Caminho de pasta inválido fornecido por <login_name>."},
            {7005, "Arquivo de índice decriptado com sucesso para <login_name>."},
            {7006, "Arquivo de índice verificado (integridade e autenticidade) com sucesso para <login_name>."},
            {7007, "Falha na decriptação do arquivo de índice para <login_name>."},
            {7008, "Falha na verificação (integridade e autenticidade) do arquivo de índice para <login_name>."},
            {7009, "Lista de arquivos presentes no índice apresentada para <login_name>."},
            {7010, "Arquivo de share decriptado com sucesso para <login_name>."},
            {7011, "Arquivo de share verificado (integridade e autenticidade) com sucesso para <login_name>."},
            {7012, "Falha na decriptação do arquivo de share para <login_name>."},
            {7013, "Falha na verificação (integridade e autenticidade) do arquivo de share para <login_name>."},
            {7014, "Lista de arquivos presentes no share apresentada para <login_name>."},
            {7015, "Arquivo <arq_name> selecionado por <login_name> para decriptação."},
            {7016, "Acesso permitido ao arquivo <arq_name> para <login_name>."},
            {7017, "Acesso negado ao arquivo <arq_name> para <login_name>."},
            {7018, "Arquivo <arq_name> decriptado com sucesso para <login_name>."},
            {7019, "Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>."},
            {7020, "Falha na decriptação do arquivo <arq_name> para <login_name>."},
            {7021, "Falha na verificação (integridade e autenticidade) do arquivo <arq_name> para <login_name>."},
            {8001, "Tela de saída apresentada para <login_name>."},
            {8002, "Botão encerrar sessão pressionado por <login_name>."},
            {8003, "Botão encerrar sistema pressionado por <login_name>."},
            {8004, "Botão voltar de sair para o menu principal pressionado por <login_name>."},
    };

    private static void carregarMensagens(Connection c) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT OR IGNORE INTO Mensagens (MID, TEXTO) VALUES (?, ?)")) {
            for (Object[] m : MENSAGENS) {
                ps.setInt(1, (Integer) m[0]);
                ps.setString(2, (String) m[1]);
                ps.executeUpdate();
            }
        }
    }
}