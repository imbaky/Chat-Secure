package codebase;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.io.FilterOutputStream.*;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import infrastructure.ChatClient;

/**
 * ChatClient implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * 
 * Here MyChatClient (of your choice) extends it and implements the actual
 * client-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 *
 * Note that A and B are distinguished by the boolean value with the
 * constructor.
 */
class MyChatClient extends ChatClient {

	String ivString = "1234567890987654321";
	byte[] iv;
	Cipher cipher;
	IvParameterSpec ivParams;
	
	// This is the minimum constructor you must preserve
	MyChatClient(boolean IsA) { 
		
		super(IsA); // IsA indicates whether it's client A or B
		startComm(); // starts the communication
		
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/** The current user that is logged in on this client **/
	public String curUser = "";
	private SecretKey chatKey;
	private Cipher c;
	/** The Json array storing the internal history state */
	JsonArray chatlog;

	/**
	 * Actions received from UI
	 */

	/**
	 * Someone clicks on the "Login" button
	 */
	public void LoginRequestReceived(String uid, String pwd) {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.LOGIN;
		p.uid = uid;
		p.password = pwd;

		SerializeNSend(p);
	}
	
	/**
	 * Callback invoked when the certificate file is selected
	 * @param path Selected certificate file's path
	 */
	public void FileLocationReceivedCert(File path) {
		// TODO
	}
	
	/**
	 * Callback invoked when the private key file is selected
	 * @param path Selected private key file's path
	 */
	public void FileLocationReceivedPriv(File path) {
		// TODO 
	}
	
	/**
	 * Callback invoked when an authentication mode is selected. 
	 * @param IsPWD True if password-based (false if certificate-based).
	 */
	public void ReceivedMode(boolean IsPWD) {
		// TODO
	}


	/**
	 * Someone clicks on the "Logout" button
	 */
	public void LogoutRequestReceived() {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.LOGOUT;

		SerializeNSend(p);
	}

	/**
	 * Someone clicks on the "Send" button
	 * @param message Message to be sent (user's level)
	 */
	public void ChatRequestReceived(byte[] message) {
		ChatPacket p = new ChatPacket();
		p.request = ChatRequest.CHAT;
		p.uid = curUser;
		p.data = message;
		SerializeNSend(p);
	}

	/**
	 * Methods for updating UI
	 */

	/**
	 * This will refresh the messages on the UI with the Json array chatlog
	 */
	void RefreshList() {
		String[] list = new String[chatlog.size()];
		for (int i = 0; i < chatlog.size(); i++) {
			String from = chatlog.getJsonObject(i).getString("from");
			String to = chatlog.getJsonObject(i).getString("to");
			String message = chatlog.getJsonObject(i).getString("message");			
			list[i] = (from + "->" + to + ": " + message);
		}
		UpdateMessages(list);
	}

	/**
	 * Methods invoked by the network stack
	 */

	/**
	 * Callback invoked when a packet has been received from the server
	 * (as the client only talks with the server, but not the other client)
	 * @param buf Incoming message
	 */
	public void PacketfromServer(byte[] buf) {
		ByteArrayInputStream is = new ByteArrayInputStream(buf);
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(is);
			Object o = in.readObject();
			ChatPacket p = (ChatPacket) o;

			if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGIN")) {
				// This indicates a successful login
				curUser = p.uid;
				chatKey = p.chatLogKey;
				
				//Initialize the IV using the chatKey (Password based)
				iv = Arrays.copyOf(chatKey.toString().getBytes(), 16);
				ivParams = new IvParameterSpec(iv);
				
				// Time to load the chatlog
				InputStream ins = null;
				JsonReader jsonReader;
				File f = new File(this.getChatLogPath());
				if (f.exists() && !f.isDirectory()) {
					try {
						ins = new FileInputStream(this.getChatLogPath());
						
						BufferedReader buffReader = new BufferedReader(new InputStreamReader(ins));

						String chatString = "";
					
						//initialize the first line
						String line = buffReader.readLine();
						
						//read the buffReader in chatString
						while(line != null){
							line = buffReader.readLine();
							chatString = chatString + line;
						}
						
						//housekeeping
						buffReader.close();
						
						//Decrypt the resulting chatString
						chatString = Decrypt(chatString);
						
						//Json.createReader requires a reader as param
						StringReader reader = new StringReader(chatString);
						
						jsonReader = Json.createReader(reader);
						chatlog = jsonReader.readArray();
						
					} catch (FileNotFoundException e) {
						System.err.println("Chatlog file could not be opened.");
					}
				} else {
					try {
						f.createNewFile();
						ins = new FileInputStream(this.getChatLogPath());
						chatlog = Json.createArrayBuilder().build();
					} catch (IOException e) {
						System.err.println("Chatlog file could not be created or opened.");
					}
				}
				RefreshList();

			} else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGOUT")) {
				// Logged out, save chat log and clear messages on the UI
				SaveChatHistory();
				curUser = "";
				UpdateMessages(null);
			} else if (p.request == ChatRequest.CHAT && !curUser.equals("")) {
				// A new chat message received
				Add1Message(p.uid, curUser, p.data);
			} else if (p.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
				// This was sent by us and now it's confirmed by the server, add
				// it to chat history
				Add1Message(curUser, p.uid, p.data);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Gives the path of the local chat history file (user-based)
	 */
	private String getChatLogPath() {
		return "log/chatlog-" + curUser + ".json";
	}

	/**
	 * Methods dealing with local processing
	 */

	/**
	 * This method saves the Json array storing the chat log back to file
	 */
	public void SaveChatHistory() {
		if (curUser.equals(""))
			return;
		try {
			// The chatlog file is named after both the client and the user
			// logged in
			
			OutputStream out = new FileOutputStream(this.getChatLogPath());
			
			//Replaced the json writer with a classic writer so that I can encrypt the entire chatlog 
			Writer writer = new OutputStreamWriter(out);
			
			//write the encryted chatlog 
			writer.write(Encrypt(chatlog.toString()));
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Similar to the one in MyChatServer, serializes and send the Java object
	 * @param p ChatPacket to serialize and send
	 */
	private void SerializeNSend(ChatPacket p) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
			out = new ObjectOutputStream(os);
			out.writeObject(p);
			byte[] packet = os.toByteArray();
			SendtoServer(packet);
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
	 * Adds a message to the internal's client state 
	 * @param from From whom the message comes from
	 * @param to To whom the messaged is addressed
	 * @param buf Message
	 */
	private void Add1Message(String from, String to, byte[] buf) {
		
		JsonArrayBuilder builder = Json.createArrayBuilder();
		for (int i = 0; i < chatlog.size(); i++) {
			builder.add(chatlog.getJsonObject(i));
		}
	
		builder.add(Json.createObjectBuilder().add("from", from).add("to", to).add("time", "").add("message", new String(buf, StandardCharsets.UTF_8)));
		JsonArray newl = builder.build();
		chatlog = newl;
		RefreshList();

	}
	
	public synchronized String Encrypt(String message)
	{
		 try{

			// initialize Encrypt Mode cipher 
            cipher.init(Cipher.ENCRYPT_MODE, chatKey, ivParams );
                      
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
	
	public synchronized String Decrypt(String message)
	{
		 try{
			 
			 	//initialize decrypt mode cipher
				cipher.init(Cipher.DECRYPT_MODE, chatKey, ivParams);
 	            
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
