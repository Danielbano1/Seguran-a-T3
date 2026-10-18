package dados;

import modelo.Chaveiro;
import modelo.Usuario;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Acesso a Usuarios e Chaveiro. Sempre PreparedStatement. */
public class UsuarioDAO {

    // ---------- cadastro ----------

    /**
     * Grava usuario + chaveiro numa transacao so (dependencia circular UID/KID):
     * 1) usuario com KID nulo, 2) chaveiro com o UID gerado, 3) atualiza o KID.
     * @return o UID gerado
     */
    public static int inserirComChaveiro(Usuario u, String certificadoPem, byte[] chavePrivadaCifrada)
            throws SQLException {
        try (Connection c = Banco.conectar()) {
            c.setAutoCommit(false);
            try {
                int uid;
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO Usuarios (LOGIN, NOME, GID, KID, SENHA_HASH, TOTP_CIFRADO) "
                                + "VALUES (?, ?, ?, NULL, ?, ?)", Statement.RETURN_GENERATED_KEYS)) {
                    ps.setString(1, u.login);
                    ps.setString(2, u.nome);
                    ps.setInt(3, u.gid);
                    ps.setString(4, u.senhaHash);
                    ps.setBytes(5, u.totpCifrado);
                    ps.executeUpdate();
                    try (ResultSet rs = ps.getGeneratedKeys()) {
                        rs.next();
                        uid = rs.getInt(1);
                    }
                }

                int kid;
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO Chaveiro (UID, CERTIFICADO_PEM, CHAVE_PRIVADA) VALUES (?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS)) {
                    ps.setInt(1, uid);
                    ps.setString(2, certificadoPem);
                    ps.setBytes(3, chavePrivadaCifrada);
                    ps.executeUpdate();
                    try (ResultSet rs = ps.getGeneratedKeys()) {
                        rs.next();
                        kid = rs.getInt(1);
                    }
                }

                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE Usuarios SET KID = ? WHERE UID = ?")) {
                    ps.setInt(1, kid);
                    ps.setInt(2, uid);
                    ps.executeUpdate();
                }

                c.commit();
                return uid;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    // ---------- consultas ----------

    public static int contarUsuarios() throws SQLException {
        try (Connection c = Banco.conectar();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM Usuarios")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    public static boolean existeLogin(String login) throws SQLException {
        return buscarPorLogin(login) != null;
    }

    /** @return o usuario ou null se o login nao existir */
    public static Usuario buscarPorLogin(String login) throws SQLException {
        try (Connection c = Banco.conectar();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM Usuarios WHERE LOGIN = ?")) {
            ps.setString(1, login);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapear(rs) : null;
            }
        }
    }

    /** Administrador cadastrado na primeira partida (usado para validar a frase no boot). */
    public static Usuario buscarPrimeiroAdmin() throws SQLException {
        try (Connection c = Banco.conectar();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT * FROM Usuarios WHERE GID = ? ORDER BY UID LIMIT 1")) {
            ps.setInt(1, Usuario.GRUPO_ADMIN);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapear(rs) : null;
            }
        }
    }

    public static Chaveiro buscarChaveiroPorUid(int uid) throws SQLException {
        try (Connection c = Banco.conectar();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM Chaveiro WHERE UID = ?")) {
            ps.setInt(1, uid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapearChaveiro(rs) : null;
            }
        }
    }

    /** Util na extracao: acha o certificado do dono do arquivo pelo e-mail que esta no index. */
    public static Chaveiro buscarChaveiroPorLogin(String login) throws SQLException {
        try (Connection c = Banco.conectar();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT k.* FROM Chaveiro k JOIN Usuarios u ON u.UID = k.UID WHERE u.LOGIN = ?")) {
            ps.setString(1, login);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapearChaveiro(rs) : null;
            }
        }
    }

    // ---------- contadores e bloqueio ----------

    /** @return o novo total de erros de senha consecutivos */
    public static int incrementarErroSenha(int uid) throws SQLException {
        return incrementar(uid, "ERROS_SENHA");
    }

    /** @return o novo total de erros de token consecutivos */
    public static int incrementarErroToken(int uid) throws SQLException {
        return incrementar(uid, "ERROS_TOKEN");
    }

    public static void zerarErrosSenha(int uid) throws SQLException { executar(uid, "UPDATE Usuarios SET ERROS_SENHA = 0 WHERE UID = ?"); }

    public static void zerarErrosToken(int uid) throws SQLException { executar(uid, "UPDATE Usuarios SET ERROS_TOKEN = 0 WHERE UID = ?"); }

    /** Bloqueia ate o instante dado (epoch em ms) e zera os dois contadores. */
    public static void bloquearAte(int uid, long ateEmMs) throws SQLException {
        try (Connection c = Banco.conectar();
             PreparedStatement ps = c.prepareStatement(
                     "UPDATE Usuarios SET BLOQUEADO_ATE = ?, ERROS_SENHA = 0, ERROS_TOKEN = 0 WHERE UID = ?")) {
            ps.setLong(1, ateEmMs);
            ps.setInt(2, uid);
            ps.executeUpdate();
        }
    }

    public static void incrementarAcessos(int uid) throws SQLException {
        executar(uid, "UPDATE Usuarios SET TOTAL_ACESSOS = TOTAL_ACESSOS + 1 WHERE UID = ?");
    }

    public static void incrementarConsultas(int uid) throws SQLException {
        executar(uid, "UPDATE Usuarios SET TOTAL_CONSULTAS = TOTAL_CONSULTAS + 1 WHERE UID = ?");
    }

    // ---------- internos ----------

    // "coluna" vem sempre de constante interna (nunca de entrada do usuario)
    private static int incrementar(int uid, String coluna) throws SQLException {
        try (Connection c = Banco.conectar()) {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE Usuarios SET " + coluna + " = " + coluna + " + 1 WHERE UID = ?")) {
                ps.setInt(1, uid);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT " + coluna + " FROM Usuarios WHERE UID = ?")) {
                ps.setInt(1, uid);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        }
    }

    private static void executar(int uid, String sql) throws SQLException {
        try (Connection c = Banco.conectar(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, uid);
            ps.executeUpdate();
        }
    }

    private static Usuario mapear(ResultSet rs) throws SQLException {
        Usuario u = new Usuario();
        u.uid = rs.getInt("UID");
        u.login = rs.getString("LOGIN");
        u.nome = rs.getString("NOME");
        u.gid = rs.getInt("GID");
        int kid = rs.getInt("KID");
        u.kid = rs.wasNull() ? null : kid;
        u.senhaHash = rs.getString("SENHA_HASH");
        u.totpCifrado = rs.getBytes("TOTP_CIFRADO");
        u.totalAcessos = rs.getInt("TOTAL_ACESSOS");
        u.totalConsultas = rs.getInt("TOTAL_CONSULTAS");
        u.errosSenha = rs.getInt("ERROS_SENHA");
        u.errosToken = rs.getInt("ERROS_TOKEN");
        u.bloqueadoAte = rs.getLong("BLOQUEADO_ATE");
        return u;
    }

    private static Chaveiro mapearChaveiro(ResultSet rs) throws SQLException {
        Chaveiro k = new Chaveiro();
        k.kid = rs.getInt("KID");
        k.uid = rs.getInt("UID");
        k.certificadoPem = rs.getString("CERTIFICADO_PEM");
        k.chavePrivadaCifrada = rs.getBytes("CHAVE_PRIVADA");
        return k;
    }
}
