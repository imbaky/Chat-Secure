package codebase;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class RSAUtils {
	static Cipher cipher;
	public RSAUtils(){
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public static synchronized String Encrypt(String message, PublicKey pubKey)
	{
		 try{

			// initialize Encrypt Mode cipher 
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);                      
            //Encrypt
            byte[] bytesMessage = cipher.doFinal(message.getBytes());
            
            //Encode
            String encryptedMessage = Base64.getEncoder().encodeToString(bytesMessage);

            return encryptedMessage;
         	
         }catch(Exception e){
         	System.err.println("Encrypt: " + e.getMessage());
         }
		 return null;
	}
	
	public static synchronized String Decrypt(String message, PrivateKey privKey)
	{
		 try{
			 
			 	//initialize decrypt mode cipher
				cipher.init(Cipher.DECRYPT_MODE, privKey);                      
 	            
				//Decode
				byte[] bytesMessage = Base64.getDecoder().decode(message);
				
				//Decrypt
 	            byte[] plainTextBytes = cipher.doFinal(bytesMessage);

 	            return new String(plainTextBytes);
	         	
	         }catch(Exception e){
	         	System.err.println("Decrypt: " + e.getMessage());
	         }
			 return null;
	
	}
	public static PublicKey loadCertificate(File path) {
		try {
			
			FileInputStream fis=new FileInputStream(path);
			CertificateFactory cf=CertificateFactory.getInstance("X.509");
			Certificate cert=cf.generateCertificate(fis);
			
			return(cert.getPublicKey());
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	public static PrivateKey loadPrivKey(File path) {
		try{

		    File f = path;
		    FileInputStream fis = new FileInputStream(f);
		    DataInputStream dis = new DataInputStream(fis);
		    byte[] keyBytes = new byte[(int)f.length()];
		    dis.readFully(keyBytes);
		    dis.close();

		    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    PrivateKey privateKey =  kf.generatePrivate(spec);
		    return privateKey;
		
	}catch(Exception e){
		
		System.err.println(e.getMessage());
		
	}
		return null;
	}
	
}
