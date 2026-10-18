package dados;

import servico.LogService;

public class BancoTeste {
    public static void main(String[] args) throws Exception {
        Banco.inicializar();
        System.out.println("Sem usuarios? " + Banco.semUsuarios());   // true
        LogService.registrar(LogService.SISTEMA_INICIADO);
    }
}
