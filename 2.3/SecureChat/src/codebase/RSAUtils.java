package codebase;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
}
