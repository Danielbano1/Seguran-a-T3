package modelo;

/** Linha da tabela Usuarios. Campos publicos de proposito: e so um portador de dados. */
public class Usuario {
    public int uid;
    public String login;          // e-mail do certificado
    public String nome;           // CN do certificado
    public int gid;               // 1 = Administrador, 2 = Usuario
    public Integer kid;           // chave do Chaveiro (nulo so durante o cadastro)
    public String senhaHash;      // bcrypt 2y, custo 8
    public byte[] totpCifrado;    // BASE32 do segredo TOTP, cifrado com AES
    public int totalAcessos;
    public int totalConsultas;
    public int errosSenha;
    public int errosToken;
    public long bloqueadoAte;     // epoch em ms; 0 = nunca bloqueado

    public static final int GRUPO_ADMIN = 1;
    public static final int GRUPO_USUARIO = 2;

    public boolean isAdmin() { return gid == GRUPO_ADMIN; }

    public String nomeDoGrupo() { return isAdmin() ? "Administrador" : "Usuário"; }

    public boolean estaBloqueado() { return System.currentTimeMillis() < bloqueadoAte; }
}