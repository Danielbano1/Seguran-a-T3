package modelo;

/** Linha da tabela Chaveiro: certificado (PEM) e chave privada ja criptografada. */
public class Chaveiro {
    public int kid;
    public int uid;
    public String certificadoPem;
    public byte[] chavePrivadaCifrada;   // bytes do .key, como vieram do arquivo
}