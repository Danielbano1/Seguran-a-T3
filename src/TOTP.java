import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

public class TOTP {
    private byte[] key = null;
    private long timeStepInSeconds = 30;

    // Recebe a chave secreta em BASE32 e o intervalo de tempo (default = 30 s).
    // Decodifica a chave e guarda em key. Em caso de erro, gera Exception.
    public TOTP(String base32EncodedSecret, long timeStepInSeconds) throws Exception {
        if (base32EncodedSecret == null || timeStepInSeconds <= 0) {
            throw new Exception("Parametros invalidos para o TOTP");
        }
        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        byte[] decoded = base32.fromString(base32EncodedSecret);
        if (decoded == null || decoded.length == 0) {
            throw new Exception("Chave secreta BASE32 invalida");
        }
        this.key = decoded;
        this.timeStepInSeconds = timeStepInSeconds;
    }

    // Recebe o HASH HMAC-SHA1 e determina o codigo TOTP de 6 algarismos
    // decimais, prefixado com zeros quando necessario (truncamento dinamico, RFC 4226).
    private String getTOTPCodeFromHash(byte[] hash) {
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                |  (hash[offset + 3] & 0xFF);
        int otp = binary % 1000000;
        return String.format("%06d", otp);
    }

    // Recebe o contador (8 bytes, big-endian) e a chave secreta e produz o HMAC-SHA1.
    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
            return mac.doFinal(counter);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao calcular HMAC-SHA1", e);
        }
    }

    // Recebe o intervalo de tempo e executa o algoritmo TOTP.
    private String TOTPCode(long timeInterval) {
        byte[] counter = new byte[8];
        for (int i = 7; i >= 0; i--) {
            counter[i] = (byte) (timeInterval & 0xFF);
            timeInterval >>= 8;
        }
        byte[] hash = HMAC_SHA1(counter, key);
        return getTOTPCodeFromHash(hash);
    }

    // Gera o codigo TOTP do instante atual.
    public String generateCode() {
        long interval = new Date().getTime() / 1000 / timeStepInSeconds;
        return TOTPCode(interval);
    }

    // Valida um codigo TOTP considerando atraso/adiantamento de 30 s (3 valores).
    public boolean validateCode(String inputTOTP) {
        if (inputTOTP == null) return false;
        String input = inputTOTP.trim();
        long current = new Date().getTime() / 1000 / timeStepInSeconds;
        boolean valid = false;
        for (long t = current - 1; t <= current + 1; t++) {
            // sem "return" antecipado: calcula os tres valores sempre
            if (TOTPCode(t).equals(input)) valid = true;
        }
        return valid;
    }
}