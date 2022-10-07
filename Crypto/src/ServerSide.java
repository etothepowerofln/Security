/**
 *
 * @author Luiz Filipi de Sousa Moura
 */

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.Scrypt;
import org.bouncycastle.util.Strings;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import de.taimos.totp.TOTP;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import org.apache.commons.codec.DecoderException;

public class ServerSide {
    
    //ScreenLogin sl = new ScreenLogin();
    private Map<String, byte[]> salts = new HashMap<String, byte[]>();
    private List<String> credentials = new ArrayList<>();
    private String chatKey = null;
    private SecretKey chatHmacKey = null;
    
    public static byte[] useScryptKDF(char[] password,
            byte [] salt, int costParameter, int blocksize, int parallelizationParam ) {
                
        KDFCalculator<Scrypt.Parameters> calculator
                = new Scrypt.KDFFactory()
                        .createKDFCalculator(
                                Scrypt.ALGORITHM.using(salt, costParameter, blocksize, parallelizationParam,
                                        Strings.toUTF8ByteArray(password)));
        byte[] output = new byte[32];
        calculator.generateBytes(output);
        return output;
    }
    
    private static byte[] decryptWithAES(String pK, byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Server:AES-decrypt");
        System.out.println("Msg = " + Hex.encodeHexString(input));
        System.out.println("Key = " + pK);
        
        Key key;
        
        byte[] K = org.apache.commons.codec.binary.Hex.decodeHex(pK.toCharArray());
        key = new SecretKeySpec(K, "AES");

        String pN;
        if (pK.length() > 24) {
            pN = pK.substring(0, 24);
        } else {
            pN = pK;
        }
        System.out.println("IV = " + pN);
        byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, N));
        byte[] plainText = cipher.doFinal(input);
        System.out.println("Msg decrypted = " + Hex.encodeHexString(plainText));
        System.out.println("##Server:AES-decrypt");
        return plainText;
    }
    
    private static String decryptTextWithAES(String pK, byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Server:AES-decrypt");
        System.out.println("Msg = " + Hex.encodeHexString(input));
        System.out.println("Key = " + pK);
        
        Key key;
        
        byte[] K = org.apache.commons.codec.binary.Hex.decodeHex(pK.toCharArray());
        key = new SecretKeySpec(K, "AES");

        String pN;
        if (pK.length() > 24) {
            pN = pK.substring(0, 24);
        } else {
            pN = pK;
        }
        System.out.println("IV = " + pN);
        byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, N));
        byte[] plainText = cipher.doFinal(input);
        System.out.println("Msg decrypted = " + Hex.encodeHexString(plainText));
        System.out.println("##Server:AES-decrypt");
        return new String(plainText, "ISO-8859-1");
    }
    
    private static byte[] encryptTextWithAES(String pK, String input) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Server:AES-encrypt");
        
        System.out.println("Msg = " + input);
        System.out.println("Key = " + pK);
        
        Key key;
        
        byte[] K = org.apache.commons.codec.binary.Hex.decodeHex(pK.toCharArray());
        key = new SecretKeySpec(K, "AES");

        String pN;
        if (pK.length() > 24) {
            pN = pK.substring(0, 24);
        } else {
            pN = pK;
        }
        System.out.println("IV = " + pN);
        byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, N));
        byte[] P = input.getBytes("ISO-8859-1");
        byte[] encryptedText = cipher.doFinal(P);
        System.out.println("Msg encrypted = " + Hex.encodeHexString(encryptedText));
        System.out.println("##Server:AES-encrypt");
        return encryptedText;
    }
    
    public static SecretKey generateHmacKey() throws GeneralSecurityException {
        System.out.println("--Server:GenerateKey-HMAC");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512", "BCFIPS");
        keyGenerator.init(256);
        System.out.println("##Server:GenerateKey-HMAC");
        return keyGenerator.generateKey();
    }

    public static byte[] calculateHmac(SecretKey key, byte[] data) throws GeneralSecurityException {
        System.out.println("--Server:HMAC");
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");
        hmac.init(key);
        System.out.println("##Server:HMAC");
        return hmac.doFinal(data);
    }
    
    public byte[] generateSalt() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        System.out.println("--Server:GenerateSalt");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        System.out.println("Generated salt:    " + Hex.encodeHexString(salt));
        System.out.println("##Server:GenerateSalt");
        return salt;
    }
    
    public byte[] getSalt(String user) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] salt = null;
        System.out.println("--Server:GetStoredSalt");
        if(salts.containsKey(user)) {
            salt = salts.get(user);
        }
        System.out.println("Recovered salt:    " + Hex.encodeHexString(salt));
        System.out.println("##Server:GetStoredSalt");
        return salt;
    }
    
    public static String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }
    
    public static String getTOTPCode(String secretKey) {
        System.out.println("--Server:GenerateTOTP-2FA");
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        String TOTPcode = TOTP.getOTP(hexKey);
        System.out.println("Key = " + secretKey);
        System.out.println("TOTP Code = " + TOTPcode);
        System.out.println("##Server:GenerateTOTP-2FA");
        return TOTPcode;
    }
    
    private static String generateDerivedKey(
                    String password, String salt, 
                    Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(), 
                    salt.getBytes(), 
                    iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
        }
        return derivedPass;
    }
    
    private static String generatePBKDF2(String senha, String salt) throws NoSuchAlgorithmException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        
        int it = 1000;
        
        System.out.println("--Server:PBKDF2");
        System.out.println("Key = " + senha);
        System.out.println("Salt = " + salt);
        System.out.println("Iter = " + it);
        
        String chaveDerivada = generateDerivedKey(senha, salt, it);
       
        System.out.println("Generated key = " + chaveDerivada );
        System.out.println("##Server:PBKDF2");
        return chaveDerivada;
    }
    
    public String readMessageFromClient(byte[] msg, byte[] hmac) throws GeneralSecurityException {
        System.out.println("--Server:ReadingMessage");
        String message = null;
        try {
            message = decryptTextWithAES(this.chatKey, msg);
            if (Arrays.equals(hmac, calculateHmac(this.chatHmacKey, msg))) {
                JOptionPane.showMessageDialog(null, message, "Message from client:", 1);
            } else {
                JOptionPane.showMessageDialog(null, "You lost your login section due to wrong HMAC.", "Wrong HMAC!", 0);
                clearChatKeys();
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(ServerSide.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Message = " + message);
        System.out.println("##Server:ReadingMessage");
        return message;
    }
        
    public byte[] sendMessageToClient(String msg) throws UnsupportedEncodingException, GeneralSecurityException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, DecoderException {
        byte[] message = encryptTextWithAES(this.chatKey, msg);
        return message;
    }
    
    public byte[] sendMessageHmacToClient(byte[] msg) throws UnsupportedEncodingException, GeneralSecurityException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, DecoderException {
        return calculateHmac(this.chatHmacKey, msg);
    }
    
    public String getChatKey() {
        return this.chatKey;
    }
    
    public SecretKey getChatHmacKey() {
        return this.chatHmacKey;
    }
    
    public boolean check2fa() throws NoSuchAlgorithmException, GeneralSecurityException, UnsupportedEncodingException {
        System.out.println("--Server:2fa");
        // Cria chave secreta simétrica
        String secret = generateSecretKey();
        
        String TOTPcode = getTOTPCode(secret);
        
        JOptionPane.showMessageDialog(null, TOTPcode, "E-MAIL", 0);
        String pass = JOptionPane.showInputDialog(null, "Enter 2fa:");
        boolean checked = pass.equals(TOTPcode);
        if(checked) {
            System.out.println("--Server:GeneratedChatKeys");
            this.chatKey = generatePBKDF2(pass, Hex.encodeHexString(generateSalt()));
            this.chatHmacKey = generateHmacKey();
            System.out.println("##Server:GeneratedChatKeys");
        }
        System.out.println("##Server:2fa");
        return checked;
    }
    
    public boolean createUser(String user, byte[] s, String entry) throws UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        
        System.out.println("--Server:SCRYPT");
        byte[] salt = null; 
        try {
            salt = decryptWithAES(entry, s);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ServerSide.class.getName()).log(Level.SEVERE, null, ex);
        }

        int costParameter = 2048;

        int blocksize = 8;

        int parallelizationParam = 1;
        
        byte[] derivedKeyFromScrypt;
        derivedKeyFromScrypt = useScryptKDF(
                entry.toCharArray(), 
                salt, costParameter,
                blocksize, parallelizationParam);

        System.out.println("Derived key using scrypt: ");
        System.out.println(Hex.encodeHexString(derivedKeyFromScrypt));
        System.out.println("##Server:SCRYPT");
        this.salts.put(user, salt);
        System.out.println(salts);
        this.credentials.add(Hex.encodeHexString(derivedKeyFromScrypt));
        System.out.println(credentials);
        return true;
    }
    
    public boolean login(byte[] s, String entry) throws UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Server:SCRYPT");
        byte[] salt = null; 
        try {
            salt = decryptWithAES(entry, s);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ServerSide.class.getName()).log(Level.SEVERE, null, ex);
        }

        int costParameter = 2048;

        int blocksize = 8;

        int parallelizationParam = 1;
        
        byte[] derivedKeyFromScrypt;
        derivedKeyFromScrypt = useScryptKDF(
                entry.toCharArray(), 
                salt, costParameter,
                blocksize, parallelizationParam);

        System.out.println("Derived key using scrypt: ");
        System.out.println(Hex.encodeHexString(derivedKeyFromScrypt));
        System.out.println("##Server:SCRYPT");
        for(String i : credentials) {
            if(i.equals(Hex.encodeHexString(derivedKeyFromScrypt))){
                return true;
            }
        }
        return false;
    }
    
    public void clearChatKeys() {
        System.out.println("--Server:DeletedChatKeys");
        this.chatKey = null;
        this.chatHmacKey = null;
        System.out.println("##Server:DeletedChatKeys");
    }
}
