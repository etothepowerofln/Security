/**
 *
 * @author Luiz Filipi de Sousa Moura
 */

import java.io.UnsupportedEncodingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import org.apache.commons.codec.DecoderException;

public class ScreenLogin extends javax.swing.JFrame {

    private static byte[] generateArgon2id(String password, byte[] salt) throws UnsupportedEncodingException {
        int opsLimit = 3;
        int memLimit = 262144;
        int outputLength = 32;
        int parallelism = 1;
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(opsLimit)
                .withMemoryAsKB(memLimit)
                .withParallelism(parallelism)
                .withSalt(salt);
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());
        byte[] result = new byte[outputLength];
        System.out.println("--Client:Argon2id");
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
        System.out.println("Argon2id = " + Hex.encodeHexString(result));
        System.out.println("##Client:Argon2id");
        return result;
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
        
        System.out.println("--Client:PBKDF2");
        System.out.println("Key = " + senha);
        System.out.println("Salt = " + salt);
        System.out.println("Iter = " + it);
        
        String chaveDerivada = generateDerivedKey(senha, salt, it);
       
        System.out.println("Generated key = " + chaveDerivada );
        System.out.println("##Client:PBKDF2");
        return chaveDerivada;
    }
    
    private static byte[] encryptWithAES(String pK, byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Client:AES-encrypt");
        
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
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, N));
        //byte[] P = input.getBytes();
        byte[] encryptedText = cipher.doFinal(input);
        System.out.println("Msg encrypted = " + Hex.encodeHexString(encryptedText));
        System.out.println("##Client:AES-encrypt");
        return encryptedText;
    }
    
    private static byte[] encryptTextWithAES(String pK, String input) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Client:AES-encrypt");
        
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
        System.out.println("##Client:AES-encrypt");
        return encryptedText;
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
    
    public static byte[] calculateHmac(SecretKey key, byte[] data) throws GeneralSecurityException {
        System.out.println("--Client:HMAC");
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");
        hmac.init(key);
        System.out.println("##Client:HMAC");
        return hmac.doFinal(data);
    }
    
    private static byte[] calculateSha3Digest(byte[] data) throws GeneralSecurityException, UnsupportedEncodingException {
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        System.out.println("--Client:SHA3");
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        System.out.println("Size in bytes SHA3-512 = " + hash.getDigestLength());
        System.out.println("Username SHA3:    " + Hex.encodeHexString(hash.digest(data)));
        System.out.println("##Client:SHA3");
        return hash.digest(data);
    }
    
    public String readMessageFromServer(String key, SecretKey hmacKey, byte[] msg, byte[] hmac) throws GeneralSecurityException, DecoderException, UnsupportedEncodingException {
        System.out.println("--Client:ReadingMessage");
        String message = null;
        try {
            message = decryptTextWithAES(key, msg);
            if (Arrays.equals(hmac, calculateHmac(hmacKey, msg))) {
                JOptionPane.showMessageDialog(null, message, "Message from server:", 1);
            } else {
                JOptionPane.showMessageDialog(null, "Wrong HMAC received, logging out.", "Wrong HMAC!", 0);
                server.clearChatKeys();
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException  ex) {
            Logger.getLogger(ServerSide.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Message = " + message);
        System.out.println("##Client:ReadingMessage");
        return message;
    }
    
    private void sendMessageToServer(String key, SecretKey hmacKey, String msg) throws UnsupportedEncodingException, GeneralSecurityException {
        try {
            byte[] message = encryptTextWithAES(key, msg);
            server.readMessageFromClient(message, calculateHmac(hmacKey, message));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void chatWithServer(String key, SecretKey hmacKey) throws UnsupportedEncodingException, GeneralSecurityException, DecoderException {
        sendMessageToServer(key, hmacKey, "Mensagem do cliente lida no servidor.\nEsta mensagem passou por criptografia autenticada e foi validada pelo MAC.");
        String readMsg = "Mensagem do servidor lida no cliente.\nEsta mensagem passou por criptografia autenticada e foi validada pelo MAC.";
        readMessageFromServer(key, hmacKey, 
                server.sendMessageToClient(readMsg), 
                server.sendMessageHmacToClient(server.sendMessageToClient(readMsg)));
    }
    
    ServerSide server = new ServerSide();
    String strUsername = null, strPassword = null,
           strUserPass = null, strArgon2id = null,
           strEncrypted = null, saltHex = null,
           strUserSHA3 = null;
    byte[] saltByte, saltEncrypted;
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jTextFieldUsername = new javax.swing.JTextField();
        jPasswordField1 = new javax.swing.JPasswordField();
        jButton1 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Liberation Sans", 1, 24)); // NOI18N
        jLabel1.setText("LOGIN SCREEN");

        jLabel2.setText("Username:");

        jLabel3.setText("Password:");

        jButton1.setText("Login");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Create user");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText("Code diagram");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addGap(104, 104, 104))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jButton3)
                        .addGap(18, 18, 18)
                        .addComponent(jButton2)
                        .addGap(18, 18, 18)
                        .addComponent(jButton1))
                    .addComponent(jTextFieldUsername)
                    .addComponent(jPasswordField1))
                .addContainerGap())
            .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.TRAILING)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextFieldUsername, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addGap(19, 19, 19)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(jButton2)
                    .addComponent(jButton3))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        strUsername = this.jTextFieldUsername.getText();
        strPassword = this.jPasswordField1.getText();
        strUserPass = strUsername + ":" + strPassword;
        
        //Username SHA3
        try {
            strUserSHA3 = Hex.encodeHexString(calculateSha3Digest(strUsername.getBytes()));
        } catch (GeneralSecurityException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //Get salt from the server
        try {
            saltByte = server.getSalt(strUserSHA3);
            if(saltByte != null) {saltHex = Hex.encodeHexString(saltByte);}
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //PBKDF2 + Argon2 in client machine
        try {
            strArgon2id = Hex.encodeHexString(generateArgon2id(generatePBKDF2(strUserPass, saltHex), saltByte));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //Encrypt salt with AES
        try {
            saltEncrypted = encryptWithAES(strArgon2id, saltByte);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            if(server.login(saltEncrypted, strArgon2id) == true) {
                if(server.check2fa()) {
                    JOptionPane.showMessageDialog(null, "Welcome, " + strUsername + "!");
                    chatWithServer(server.getChatKey(), server.getChatHmacKey());
                } else {
                    JOptionPane.showMessageDialog(null, "User not validated.");
                }
            }
        } catch (UnsupportedEncodingException | GeneralSecurityException | DecoderException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        strUsername = this.jTextFieldUsername.getText();
        strPassword = this.jPasswordField1.getText();
        strUserPass = strUsername + ":" + strPassword;
        
        //Get a random salt from the server
        try {
            saltByte = server.generateSalt();
            saltHex = Hex.encodeHexString(saltByte);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //PBKDF2 + Argon2 in client machine
        try {
            strArgon2id = Hex.encodeHexString(generateArgon2id(generatePBKDF2(strUserPass, saltHex), saltByte));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //Encrypt salt with AES
        try {
            saltEncrypted = encryptWithAES(strArgon2id, saltByte);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | DecoderException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //Username SHA3
        try {
            strUserSHA3 = Hex.encodeHexString(calculateSha3Digest(strUsername.getBytes()));
        } catch (GeneralSecurityException | UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            //Send to server
            if(server.createUser(strUserSHA3, saltEncrypted, strArgon2id) == true) {
                JOptionPane.showMessageDialog(null, "User created!");
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ScreenLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        ImageIcon dia = new ImageIcon("diagram.png");
        JOptionPane.showMessageDialog(null, dia, "Code diagram", 1);
    }//GEN-LAST:event_jButton3ActionPerformed

    public ScreenLogin() {
        initComponents();
        setLocationRelativeTo(null);
        setResizable(false);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ScreenLogin.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(() -> {
            new ScreenLogin().setVisible(true);
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    public javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JSeparator jSeparator1;
    public javax.swing.JTextField jTextFieldUsername;
    // End of variables declaration//GEN-END:variables
}
