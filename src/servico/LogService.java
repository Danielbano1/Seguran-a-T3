package servico;

import dados.Banco;
import modelo.Usuario;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

/**
 * Grava em Registros so o codigo da mensagem (MID), nunca o texto.
 * O texto fica em Mensagens; o logView troca <login_name> e <arq_name> na exibicao.
 */
public class LogService {

    // ---- Partida e sessao ----
    public static final int SISTEMA_INICIADO = 1001;
    public static final int SISTEMA_ENCERRADO = 1002;
    public static final int SESSAO_INICIADA = 1003;
    public static final int SESSAO_ENCERRADA = 1004;
    public static final int PARTIDA_CADASTRO_ADMIN = 1005;
    public static final int PARTIDA_OPERACAO_NORMAL = 1006;
    // ---- Etapa 1 ----
    public static final int ETAPA1_INICIADA = 2001;
    public static final int ETAPA1_ENCERRADA = 2002;
    public static final int LOGIN_LIBERADO = 2003;
    public static final int LOGIN_BLOQUEADO = 2004;
    public static final int LOGIN_NAO_IDENTIFICADO = 2005;
    // ---- Etapa 2 ----
    public static final int ETAPA2_INICIADA = 3001;
    public static final int ETAPA2_ENCERRADA = 3002;
    public static final int SENHA_OK = 3003;
    public static final int SENHA_ERRO_1 = 3004;
    public static final int SENHA_ERRO_2 = 3005;
    public static final int SENHA_ERRO_3 = 3006;
    public static final int BLOQUEIO_ETAPA2 = 3007;
    // ---- Etapa 3 ----
    public static final int ETAPA3_INICIADA = 4001;
    public static final int ETAPA3_ENCERRADA = 4002;
    public static final int TOKEN_OK = 4003;
    public static final int TOKEN_ERRO_1 = 4004;
    public static final int TOKEN_ERRO_2 = 4005;
    public static final int TOKEN_ERRO_3 = 4006;
    public static final int BLOQUEIO_ETAPA3 = 4007;
    // ---- Tela principal ----
    public static final int TELA_PRINCIPAL = 5001;
    public static final int MENU_OPCAO_1 = 5002;
    public static final int MENU_OPCAO_2 = 5003;
    public static final int MENU_OPCAO_3 = 5004;
    // ---- Cadastro ----
    public static final int TELA_CADASTRO = 6001;
    public static final int BOTAO_CADASTRAR = 6002;
    public static final int SENHA_PESSOAL_INVALIDA = 6003;
    public static final int CERTIFICADO_CAMINHO_INVALIDO = 6004;
    public static final int CHAVE_CAMINHO_INVALIDO = 6005;
    public static final int CHAVE_FRASE_INVALIDA = 6006;
    public static final int CHAVE_ASSINATURA_INVALIDA = 6007;
    public static final int CONFIRMACAO_ACEITA = 6008;
    public static final int CONFIRMACAO_REJEITADA = 6009;
    public static final int VOLTAR_DE_CADASTRO = 6010;
    // ---- Consulta ----
    public static final int TELA_CONSULTA = 7001;
    public static final int VOLTAR_DE_CONSULTA = 7002;
    public static final int BOTAO_LISTAR = 7003;
    public static final int PASTA_INVALIDA = 7004;
    public static final int INDEX_DECRIPTADO = 7005;
    public static final int INDEX_VERIFICADO = 7006;
    public static final int INDEX_FALHA_DECRIPTACAO = 7007;
    public static final int INDEX_FALHA_VERIFICACAO = 7008;
    public static final int INDEX_LISTA_APRESENTADA = 7009;
    public static final int SHARE_DECRIPTADO = 7010;
    public static final int SHARE_VERIFICADO = 7011;
    public static final int SHARE_FALHA_DECRIPTACAO = 7012;
    public static final int SHARE_FALHA_VERIFICACAO = 7013;
    public static final int SHARE_LISTA_APRESENTADA = 7014;
    public static final int ARQUIVO_SELECIONADO = 7015;
    public static final int ACESSO_PERMITIDO = 7016;
    public static final int ACESSO_NEGADO = 7017;
    public static final int ARQUIVO_DECRIPTADO = 7018;
    public static final int ARQUIVO_VERIFICADO = 7019;
    public static final int ARQUIVO_FALHA_DECRIPTACAO = 7020;
    public static final int ARQUIVO_FALHA_VERIFICACAO = 7021;
    // ---- Saida ----
    public static final int TELA_SAIDA = 8001;
    public static final int ENCERRAR_SESSAO = 8002;
    public static final int ENCERRAR_SISTEMA = 8003;
    public static final int VOLTAR_DE_SAIDA = 8004;

    /** Evento sem usuario (ex.: sistema iniciado). */
    public static void registrar(int mid) {
        gravar(mid, null, null, null);
    }

    /** Evento de um usuario ja identificado. */
    public static void registrar(int mid, Usuario u) {
        gravar(mid, u == null ? null : u.uid, u == null ? null : u.login, null);
    }

    /** Evento de um usuario sobre um arquivo (mensagens 7015 a 7021). */
    public static void registrar(int mid, Usuario u, String nomeArquivo) {
        gravar(mid, u == null ? null : u.uid, u == null ? null : u.login, nomeArquivo);
    }

    /** Login digitado que nao existe no banco (mensagem 2005): nao ha UID. */
    public static void registrarLogin(int mid, String loginDigitado) {
        gravar(mid, null, loginDigitado, null);
    }

    private static void gravar(int mid, Integer uid, String login, String arquivo) {
        String sql = "INSERT INTO Registros (DATA_HORA, MID, UID, LOGIN, ARQUIVO) VALUES (?, ?, ?, ?, ?)";
        try (Connection c = Banco.conectar(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setInt(2, mid);
            if (uid == null) ps.setNull(3, Types.INTEGER); else ps.setInt(3, uid);
            if (login == null) ps.setNull(4, Types.VARCHAR); else ps.setString(4, login);
            if (arquivo == null) ps.setNull(5, Types.VARCHAR); else ps.setString(5, arquivo);
            ps.executeUpdate();
        } catch (SQLException e) {
            // Falha de log nao deve derrubar a tela; avisa no console.
            System.err.println("Falha ao gravar registro " + mid + ": " + e.getMessage());
        }
    }
}