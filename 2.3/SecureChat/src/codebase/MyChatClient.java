package codebase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
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
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import infrastructure.ChatClient;
import java.security.interfaces.RSAPublicKey;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;

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

	PublicKey publicKey;
	PrivateKey privateKey;
	PublicKey serverPublicKey;
	boolean loginWPass=true;
	
	MyChatClient(boolean IsA) { // This is the minimum constructor you must
								// preserve
		super(IsA); // IsA indicates whether it's client A or B
		startComm(); // starts the communication
		File serverCert = new File("../myroot/server.crt");
		serverPublicKey = loadCertificate(serverCert);
	}

	/** The current user that is logged in on this client **/
	public String curUser = "";

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
		//@Reference code given in tutorial slides
		this.publicKey = loadCertificate(path);
		
	}


	public PublicKey loadCertificate(File path) {
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
	
	/**
	 * Callback invoked when the private key file is selected
	 * @param path Selected private key file's path
	 */
	public void FileLocationReceivedPriv(File path) {
		
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
			    this.privateKey= privateKey;
			    System.out.println(privateKey.getFormat());
		}catch(Exception e){
			
			System.err.println(e.getMessage());
			
		}
		
		
	}
	
	/**
	 * Callback invoked when an authentication mode is selected. 
	 * @param IsPWD True if password-based (false if certificate-based).
	 */
	public void ReceivedMode(boolean IsPWD) {
		// TODO
		this.loginWPass=IsPWD;		
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
	/*
	 * try {
		Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte [] cipherText=cipher.doFinal("Hello".getBytes());
		System.err.println(cipherText);
	
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		System.err.println(new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8));
		
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}*/
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

				// Time to load the chatlog
				InputStream ins = null;
				JsonReader jsonReader;
				File f = new File(this.getChatLogPath());
				if (f.exists() && !f.isDirectory()) {
					try {
						ins = new FileInputStream(this.getChatLogPath());
						jsonReader = Json.createReader(ins);
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
			JsonWriter writer = Json.createWriter(out);
			writer.writeArray(chatlog);
			writer.close();
		} catch (FileNotFoundException e) {
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
		try {
			builder.add(Json.createObjectBuilder().add("from", from).add("to", to).add("time", "").add("message",
					new String(buf, "UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		JsonArray newl = builder.build();
		chatlog = newl;
		RefreshList();

	}
}
