package codebase;

import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

import infrastructure.ChatServer;

/**
 * ChatServer implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * 
 * Here MyChatServer (of your choice) extends it and implements the actual
 * server-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 *
 */
class MyChatServer extends ChatServer {
	
	/** A Json array loaded from disk file storing plaintext uids and pwds. */
	JsonArray database;
	SecureRandom csprng = new SecureRandom();	
	MessageDigest md;
	byte[] temp;
	
	/**
	 * Client login status; "" indicates not logged in or otherwise is set to
	 * uid.
	 **/
	String statA = "";
	String statB = "";

	// In Constructor, the user database is loaded.
	MyChatServer() {
		
		try{
			md = MessageDigest.getInstance("SHA-256");
			
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		
		
		try {
			InputStream in = new FileInputStream("database.json");
			JsonReader jsonReader = Json.createReader(in);
			database = jsonReader.readArray();

		} catch (FileNotFoundException e) {
			System.err.println("Database file not found!");
			System.exit(-1);
		}

	}

	/**
	 * Methods invoked by the network stack
	 */

	/**
	 * Overrides the function in ChatServer Whenever a packet is received this
	 * method is called and IsA indicates whether it is from A (or B) with the
	 * byte array of the raw packet
	 */
	public void PacketReceived(boolean IsA, byte[] buf) {
		ByteArrayInputStream is = new ByteArrayInputStream(buf);
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(is);
			Object o = in.readObject();
			ChatPacket p = (ChatPacket) o;
			
			if (p.request == ChatRequest.LOGIN) {
				
				// We want to go through all records
				for (int i = 0; i < database.size(); i++) {
					
					JsonObject l = database.getJsonObject(i);
					
					// When both uid and pwd match
					if (l.getString("uid").equals(p.uid)){

						//concatenate the salt to the user's entered pw
						String usrPwd = p.password.concat(l.getString("salt"));						
						
//						System.out.println("Base64: " + Base64.getDecoder().decode(usrPwd));
						
						//Hash(pwd||Salt)
						byte[] hashPwd = md.digest(usrPwd.getBytes());
						
						//get the hashed password for this user in the database
						String dbPwd = Arrays.toString(l.getString("password").getBytes( StandardCharsets.UTF_16LE));

						if(dbPwd.equals(Arrays.toString(hashPwd))) {
														
							// We do not allow one user to be logged in on multiple
							// clients
							if (p.uid.equals(IsA ? statB : statA))
								continue;
							
							// Update the corresponding login status
							if (IsA) {
								statA = l.getString("uid");
							} else {
								statB = l.getString("uid");
							}
							
							// Update the UI to indicate this
							UpdateLogin(IsA, l.getString("uid"));
													
							
							
							//Generate ChatKey
							//http://stackoverflow.com/questions/4513433/deriving-a-secret-from-a-master-key-using-jce-jca
							try{
								
								byte[] keyPwd;
								
								if(l.getString("uid") == "Alice")
								{
								}
								else
								{
									
								}
								
								 byte[] pwdForKey = Arrays.copyOf(usrPwd.getBytes(), 16);
								 SecretKey key = new SecretKeySpec(pwdForKey, "AES");
								 // Inform the client that it was successful
								 RespondtoClient(IsA, "LOGIN", key);
							
							}catch(Exception e){
								System.err.println(e.getMessage());
							}
							
							break;
						}
					}
				}

				if ((IsA ? statA : statB).equals("")) {
					// Oops, this means a failure, we tell the client so
					RespondtoClient(IsA, "");
				}
			} else if (p.request == ChatRequest.LOGOUT) {
				if (IsA) {
					statA = "";
				} else {
					statB = "";
				}
				UpdateLogin(IsA, "");
				RespondtoClient(IsA, "LOGOUT");
				
			} else if (p.request == ChatRequest.CHAT) {
				// This is a chat message

				// Whoever is sending it must be already logged in
				if ((IsA && statA != "") || (!IsA && statB != "")) {
					// Forward the original packet to the recipient
					SendtoClient(!IsA, buf);
					p.request = ChatRequest.CHAT_ACK;
					p.uid = (IsA ? statB : statA);

					// Flip the uid and send it back to the sender for updating
					// chat history
					SerializeNSend(IsA, p);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Methods for updating UI
	 */

	// You can use this.UpdateServerLog("anything") to update the TextField on
	// the server portion of the UI
	// when needed

	/**
	 * Methods invoked locally
	 */

	/**
	 * This method serializes (into byte[] representation) a Java object
	 * (ChatPacket) and sends it to the corresponding recipient (A or B)
	 */
	private void SerializeNSend(boolean IsA, ChatPacket p) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
			out = new ObjectOutputStream(os);
			out.writeObject(p);
			byte[] packet = os.toByteArray();
			SendtoClient(IsA, packet);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	/**
	 * This method composes the packet needed to respond to a client (indicated
	 * by IsA) regarding whether the login/logout request was successful
	 * p.success would be "" if failed or "LOGIN"/"LOGOUT" respectively if
	 * successful
	 * @param chatKey 
	 */
	void RespondtoClient(boolean IsA, String Success) {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.RESPONSE;
		p.uid = IsA ? statA : statB;
		p.success = Success;
//		p.chatLogKey = chatKey;
		SerializeNSend(IsA, p);
	}
	
	void RespondtoClient(boolean IsA, String Success, SecretKey chatKey) {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.RESPONSE;
		p.uid = IsA ? statA : statB;
		p.success = Success;
		p.chatLogKey = chatKey;
		SerializeNSend(IsA, p);
	}
	
	byte[] CreateRandomSalt(){
	
		byte[] salt = new byte[20];
		csprng.nextBytes(salt);
		return salt;
		
	}

}
