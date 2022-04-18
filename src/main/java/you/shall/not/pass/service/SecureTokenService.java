package you.shall.not.pass.service;

import org.springframework.stereotype.Service;

import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;

@Service
public class SecureTokenService {
    private final static int STANDARD_SIZE_TOKEN = 16;
    private final static SecureRandom SECURE_RANDOM = new SecureRandom();

    public String generateToken() {
        return generateToken(STANDARD_SIZE_TOKEN);
    }

    public String generateToken(int size) {
        byte[] buffer = new byte[size];
        SECURE_RANDOM.nextBytes(buffer);
        return DatatypeConverter.printHexBinary(buffer);
    }
}
