package main.java.configManager;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.json.JSONArray;
import org.json.JSONObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.src.common.ConfigurationDTO;
import com.src.dbaccess.DBManager;
import com.src.utils.Utils;

public class ConfigManager {
	
	static Logger slog = Logger.getLogger("ServerLog");
	
	private static final String strMysqlAlias = "mysqlEncryptionKey";
	private static final String strDataPasswordAlias = "dataEncryptionkey";
	private static final int SALT_LEN = 16;
	
	//private static final String aliasFileLocation = "/usr/share/tomcat6/ix_keys/";
	private static final String requestingUser = "ixoperator";
	
	private static final String keysDirectory = "ix_keys/";
	
	private static String strSelectAdapters = "SELECT distinct adapter FROM configuration ORDER BY adapter asc";

	/**
	 * This method opens a MySQL connection
	 * <p>
	 * @return connection instance if successful
	 */
	public static Connection getConnection(){
		Connection connection = null;
		try{
			System.out.println("[ConfigManager / ConfigManager / getConnection] Attempting to get MySQL connection.. ");
			slog.info("[ConfigManager / ConfigManager / getConnection] Attempting to get MySQL connection.. ");
			connection = DBManager.getConnectionToDB();
			if(null == connection)
			{
				System.out.println("[ConfigManager / ConfigManager / getConnection] Could not obtain the database connection. Cannot proceed and hence returning...");
				slog.info("[ConfigManager / ConfigManager / getConnection] Could not obtain the database connection. Cannot proceed and hence returning...");
				return null;
			}
			System.out.println("[ConfigManager / ConfigManager / getConnection] Obtained a new database connection...");
			slog.info("[ConfigManager / ConfigManager / getConnection] Obtained a new database connection...");
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getConnection] Exception occured while obtaining mysql connection. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getConnection] Exception occured while obtaining mysql connection. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getConnection]Stack trace", exc);
			exc.printStackTrace();
		}
		return connection;
	}
	
	/**
	 * This method closes the MySQL connection
	 * <p>
	 * @param connection the (@code Connection} active MySQL connection
	 */
	public static void closeConnection(Connection connection){
		try{
			if(connection != null){
				DBManager.closeConnectionToDB(connection);
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager/ closeConnection] Exception occured while closing SQL connection. Exception is:"+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager/ closeConnection] Exception occured while closing SQL connection. Exception is:"+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / closeConnection]Stack trace", exc);
			exc.printStackTrace();
		}

	}
	
	/**
	 * This method decodes the base 64 encodedString
	 * @param encodedString
	 * @return decodedString
	 */
	public static String decodeString(String encodedString){
		String decodedString = new String( Base64.decodeBase64(encodedString));
		return decodedString;
	}
	
	/**
	 * This method base64 decrypts the mySQL password string
	 * @param encryptedToken
	 * @param iv
	 * @return decrypted password if successful
	 */
	public static String decryptMySqlPassword(String encryptedToken, byte[] iv){
		String decryptedStr = null;
		try{
			String password = new String(Base64.decodeBase64(readKeyFile(Utils.getKeyStorePasswordFilePath())));
			decryptedStr = decrypt(strMysqlAlias, password, encryptedToken, iv);
			System.out.println("[ConfigManager / ConfigManager / decryptMySqlPassword] Successfully decrypted the MySQL password...");
			slog.info("[ConfigManager / ConfigManager / decryptMySqlPassword] Successfully decrypted the MySQL password...");
		}catch(IOException exc){
			System.out.println("[ConfigManager / ConfigManager / decryptMySqlPassword] IOException occured while decrypting mysql password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decryptMySqlPassword] IOException occured while decrypting mysql password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decryptMySqlPassword]Stack trace", exc);
			exc.printStackTrace();
		} catch (Exception exc) {
			System.out.println("[ConfigManager / ConfigManager / decryptMySqlPassword] Exception occured while decrypting mysql password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decryptMySqlPassword] Exception occured while decrypting mysql password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decryptMySqlPassword]Stack trace", exc);
			exc.printStackTrace();
		}
		return decryptedStr;
	}

	/**
	 * This method generates a random salt of pre defined length
	 * @return salt value in bytes if successful
	 */
	public static byte[] getRandomSalt() {
		SecureRandom random = new SecureRandom();
		byte[] saltBytes = new byte[SALT_LEN];
		random.nextBytes(saltBytes);
		return saltBytes;
	}
	
	/**
	 * This method base64 encodes and encrypts the string
	 * @param plaintext
	 * @param iv
	 * @return encrypted password string if successful
	 */
	public static String encryptDataPassword(String plaintext, byte[] iv){
		String encryptedToken = null;
		try{
			String password = new String(Base64.decodeBase64(readKeyFile(Utils.getKeyStorePasswordFilePath())));
			encryptedToken = encrypt(strDataPasswordAlias, password, plaintext, iv); //encrypt
			encryptedToken = new String(Base64.encodeBase64(encryptedToken.getBytes())); //encode
			System.out.println("[ConfigManager / ConfigManager / encryptDataPassword] Successfully encrypted the data password...");
			slog.info("[ConfigManager / ConfigManager / encryptDataPassword] Successfully encrypted the data password...");
		}
		catch (Exception exc){
			System.out.println("[ConfigManager / ConfigManager / encryptDataPassword] Exception occured while encrypting data password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encryptDataPassword] Exception occured while encrypting data password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encryptDataPassword]Stack trace", exc);
		}
		return encryptedToken;
	}

	/**
	 * This method base64 encodes and encrypts the string
	 * @param keyAlias
	 * @param keyProtectionParam
	 * @param tokenString
	 * @param iv
	 * @return encrypted string if successful
	 * @throws Exception
	 */
	public static String encrypt(String keyAlias, String keyProtectionParam, String tokenString, byte[] iv) throws Exception{
		String base64Token = null;
		try{
			KeyStore ks = getKeyStore();
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyProtectionParam.toCharArray());
			KeyStore.SecretKeyEntry  secretKeyEntry = (KeyStore.SecretKeyEntry)ks.getEntry(keyAlias, protParam);
			SecretKey key = secretKeyEntry.getSecretKey();
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
			byte[] encryptedData = cipher.doFinal(tokenString.getBytes());

			base64Token = new String(Base64.encodeBase64(encryptedData));
		}
		catch (NoSuchAlgorithmException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] NoSuchAlgorithmException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] NoSuchAlgorithmException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (NoSuchPaddingException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] NoSuchPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] NoSuchPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (InvalidKeyException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] InvalidKeyException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] InvalidKeyException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (InvalidAlgorithmParameterException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] InvalidAlgorithmParameterException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] InvalidAlgorithmParameterException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (IllegalBlockSizeException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] IllegalBlockSizeException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] IllegalBlockSizeException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (BadPaddingException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] BadPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] BadPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (UnrecoverableEntryException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] UnrecoverableEntryException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] UnrecoverableEntryException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		} catch (KeyStoreException exc) {
			System.out.println("[ConfigManager / ConfigManager / encrypt] KeyStoreException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / encrypt] KeyStoreException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / encrypt]Stack trace", exc);
		}
		return base64Token;
	}

	/**
	 * This method base64 decodes and decrypts the string
	 * @param keyAlias
	 * @param keyProtectionParam
	 * @param encodedString
	 * @param iv
	 * @return decrypted string if successful
	 */
	public static String decrypt(String keyAlias, String keyProtectionParam, String encodedString, byte[] iv){
		byte[] unencryptedBytes = null;
		try{
			KeyStore ks = getKeyStore();
			KeyStore.ProtectionParameter protParam =new KeyStore.PasswordProtection(keyProtectionParam.toCharArray());
			KeyStore.SecretKeyEntry  secretKeyEntry = (KeyStore.SecretKeyEntry)ks.getEntry(keyAlias, protParam);
			SecretKey key = secretKeyEntry.getSecretKey();
			byte[] encryptedBytes = Base64.decodeBase64(encodedString);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
			unencryptedBytes = cipher.doFinal(encryptedBytes);
		}
		catch (NoSuchAlgorithmException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] NoSuchAlgorithmException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] NoSuchAlgorithmException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (NoSuchPaddingException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] NoSuchPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] NoSuchPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (InvalidKeyException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] InvalidKeyException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] InvalidKeyException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (InvalidAlgorithmParameterException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] InvalidAlgorithmParameterException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] InvalidAlgorithmParameterException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (IllegalBlockSizeException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] IllegalBlockSizeException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] IllegalBlockSizeException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (BadPaddingException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] BadPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] BadPaddingException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (UnrecoverableEntryException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] UnrecoverableEntryException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] UnrecoverableEntryException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		} catch (KeyStoreException exc) {
			System.out.println("[ConfigManager / ConfigManager / decrypt] KeyStoreException occured while decrypting password. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / decrypt] KeyStoreException occured while decrypting password. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / decrypt]Stack trace", exc);
		}
		return new String(unencryptedBytes);
	}
	/**
	 * This method reads the password for keystore from keystore password file
	 * @param fileName
	 * @return password string for keystore file if successful
	 * @throws IOException
	 */
	public static String readKeyFile(String fileName) throws IOException {
		FileInputStream fileInputStream = null;
		StringBuffer strContent = new StringBuffer("");
		try {
			fileInputStream = new FileInputStream(new File(fileName));
			int content;
			while( (content = fileInputStream.read()) != -1)
				strContent.append((char)content);
		} finally {
			if (fileInputStream != null)
				fileInputStream.close();
		}
		return strContent.toString();
	}

	/**
	 * This method fetches the keystore file
	 * @return {@code KeyStore}, if successful, {@code null} if failed
	 */
	private static KeyStore getKeyStore(){
		FileInputStream fis = null;
		KeyStore ks = null;
		try {
			String keystorePassword = new String(Base64.decodeBase64(new String(Base64.decodeBase64(readKeyFile(Utils.getKeyStorePasswordFilePath())))));
			File keyStoreFile = null;
			keyStoreFile = new File(Utils.getKeyStoreFilePath());
			
			ks = KeyStore.getInstance("JCEKS");
			fis = new FileInputStream(keyStoreFile);
			ks.load(fis, keystorePassword.toCharArray() );
		}catch(IOException exc){
			System.out.println("[ConfigManager / ConfigManager / getKeyStore] IOException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getKeyStore] IOException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", exc);
		}catch (NoSuchAlgorithmException exc){
			System.out.println("[ConfigManager / ConfigManager / getKeyStore] NoSuchAlgorithmException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getKeyStore] NoSuchAlgorithmException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", exc);
		}catch (CertificateException exc){
			System.out.println("[ConfigManager / ConfigManager / getKeyStore] CertificateException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getKeyStore] CertificateException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", exc);
		} catch (KeyStoreException exc) {
			System.out.println("[ConfigManager / ConfigManager / getKeyStore] KeyStoreException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getKeyStore] KeyStoreException occured while fetching the keystore file. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", exc);
		}
		finally {
			if (fis != null)
				try {
					fis.close();
				} catch (IOException exc) {
					System.out.println("[ConfigManager / ConfigManager / getKeyStore] IOException occured while closing the keystore file stream. Returning failure. Exception is - " + exc.getMessage());
					exc.printStackTrace();
					slog.error("[ConfigManager / ConfigManager / getKeyStore] IOException occured while closing the keystore file stream. Returning failure. Exception is - " + exc.getMessage());
					slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", exc);
				}
		}
		return ks;
	}
	
	/**
	 * Take the command line string as entered by user and parse it
	 * @param args
	 * @return CommandLine args as an object
	 */
	public static CommandLine getCommand(String[] args) {
		
		Options options = new Options();
		options.addOption("setProperty", false, "Set Property");
		options.addOption("getProperty", false, "Get Property");
		options.addOption("getAdapters", false, "Get all Adapters");
		
		options.addOption("getAppliance",true,"Get Appliance details");
		options.addOption("setAppliance",false, "Add Appliance Details");
		options.addOption("deleteAppliance",true,"Delete Appliance record");
		
		options.addOption("getRegionView",true,"Get Region/View details");
		options.addOption("setRegionView",false, "Add Region/View Details");
		options.addOption("deleteRegionView",true,"Delete Region/View details");
		
		options.addOption("outputFormat", true, "Output Format");
		options.addOption("adapterName", true, "Adapter Name");
		options.addOption("propertyName", true, "Property Name");
		options.addOption("propertyValue", true,"Property Value");
		
		options.addOption("applianceName", true, "Appliance Hostname");
		options.addOption("applianceType", true, "Appliance Type");
		options.addOption("region", true, "Appliance Region");
		options.addOption("country", true, "Appliance Country");
		options.addOption("ipAddress", true, "Appliance IP_Address");
		options.addOption("username", true, "Appliance Username");
		options.addOption("password", true, "Appliance Password");
		options.addOption("version", true, "Appliance Version");
		
		options.addOption("regionViewName", true, "Region/View Name");
		options.addOption("readableName", true, "Region/View Readable Name");
		options.addOption("viewType", true, "Region/View Type");
		options.addOption("domainValue", true, "Domain Values");
		
		CommandLineParser parser = new DefaultParser();
		try
		{
			return parser.parse(options, args);
		}
		catch (ParseException pExc) {
			System.out.println("[ConfigManager / ConfigManager / getCommand] Error occurred obtaining parsing command line arguments. Error message is - " + pExc.getMessage());
			pExc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getCommand] Error occurred obtaining parsing command line arguments. Error message is - " + pExc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getKeyStore]Stack trace", pExc);
			return null;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getCommand] Error occurred obtaining parsing command line arguments. Error message is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager/ getCommand] Error occurred obtaining parsing command line arguments. Error message is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getCommand]Stack trace", exc);
			return null;
		}
	}
	
	/**
	 * Fetch property details from configuration table in MySQL DB for a given property name
	 * <p>
	 * This method executes the select SQL statement against the backend database. 
	 * </p>
	 * @return property details list, if successful
	 */
	public static List<ConfigurationDTO> getPropertyDetailsForPropertyName(String propertyName){
		Connection dbConn = getConnection();
		if( null == dbConn)
		{
			System.out.println("[ConfigManager / ConfigManager / getPropertyDetailsForPropertyName] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / getPropertyDetailsForPropertyName] Could not obtain the database connection. Returning");
			return null;
		}
		
		try{
			List<ConfigurationDTO> listOfProperties = new ArrayList<ConfigurationDTO>();
			String queryFetchPropertyDetailsForProperty = "SELECT * FROM configuration WHERE name like '"+ propertyName + "'";
			ResultSet propertiesFromQuery = runSelectSQLScript(dbConn,queryFetchPropertyDetailsForProperty);
			if(null != propertiesFromQuery){
				boolean bSuccess = processDetailedResultSet(propertiesFromQuery, listOfProperties);
				if(true == bSuccess){
					if(!listOfProperties.isEmpty()){
						return listOfProperties;
					}
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getPropertyDetailsForPropertyName] Exception occured while getting the properties. Returning faiure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getPropertyDetailsForPropertyName] Exception occured while getting the properties. Returning faiure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getPropertyDetailsForPropertyName]Stack trace", exc);
			
		}
		finally{
			closeConnection(dbConn);
		}
		return null;
	}
	
	/**
	 * Parse result set returned from MySQL and format the result set
	 * @param propertiesFromQuery
	 * @return concise property details as a JSON string
	 */
	private static String processConciseResultSet(ResultSet propertiesFromQuery){
		JSONArray propertyDetailsList = null;
		try{
			propertyDetailsList = new JSONArray();
			while(propertiesFromQuery.next()){
				JSONObject propertyDetails = new JSONObject();
				propertyDetails.put("Display Name", propertiesFromQuery.getString("display_name"));
				propertyDetails.put("Adapter Name", propertiesFromQuery.getString("adapter"));
				propertyDetails.put("Property Name", propertiesFromQuery.getString("name"));
				String controlType = propertiesFromQuery.getString("control_type");
				if(null != controlType && false == controlType.isEmpty()){
					if(controlType.equalsIgnoreCase("PasswordTextBox")){
						propertyDetails.put("Property Value", "********");
					}
					else{
						propertyDetails.put("Property Value", propertiesFromQuery.getString("value"));
					}
				}
				
				propertyDetailsList.put(propertyDetails);
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / processConciseResultSet] Error occurred while formatting SQL result set. Error message is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / processConciseResultSet] Error occurred while formatting SQL result set. Error message is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / processConciseResultSet]Stack trace", exc);
			return null;
		}
		
		return propertyDetailsList.toString();
	}
	/**
	 * Process result set from MySQL database into a list of ConfigurationDTO Objects
	 * @return true, if successful
	 */
	private static boolean processDetailedResultSet(ResultSet propertiesFromQuery, List<ConfigurationDTO> listOfProperties){
		
		try{
			
			while (propertiesFromQuery.next()){
				
				ConfigurationDTO propertyRecord = new ConfigurationDTO();
				propertyRecord.setAdapter(propertiesFromQuery.getString("adapter"));
				propertyRecord.setSection(propertiesFromQuery.getString("section"));
				propertyRecord.setName(propertiesFromQuery.getString("name"));
				propertyRecord.setDisplay_name(propertiesFromQuery.getString("display_name"));
				propertyRecord.setSequence(propertiesFromQuery.getInt("sequence"));
				propertyRecord.setDescription(propertiesFromQuery.getString("description"));
				propertyRecord.setTool_tip(propertiesFromQuery.getString("tool_tip"));
				propertyRecord.setControl_type(propertiesFromQuery.getString("control_type"));
				propertyRecord.setData_type(propertiesFromQuery.getString("data_type"));
				
				if(propertiesFromQuery.getString("value").equalsIgnoreCase("FILE_UPLOAD")){
					System.out.println("[ConfigManager / ConfigManager / processDetailedResultSet]Error occurred.. Data Type is 'FILE_UPLOAD'.. Cannot continue.. Returning failure..");
					slog.error("[ConfigManager / ConfigManager / processDetailedResultSet]Error occurred.. Data Type is 'FILE_UPLOAD'.. Cannot continue.. Returning failure..");
					return false;
					
				}
				else{
					propertyRecord.setValue(propertiesFromQuery.getString("value"));
				}
				propertyRecord.setSalt_Value(propertiesFromQuery.getString("salt_value"));
				propertyRecord.setUpload_directory(propertiesFromQuery.getString("upload_directory"));
				propertyRecord.setUpload_File_Name(propertiesFromQuery.getString("upload_file_name"));
				propertyRecord.setUpload_File_Type_URI(propertiesFromQuery.getString("upload_file_type_URI"));
				propertyRecord.setSupported_file_formats(propertiesFromQuery.getString("supported_file_formats"));
				propertyRecord.setMax_upload_file_size(propertiesFromQuery.getInt("max_upload_file_size"));
				propertyRecord.setSupported_values(propertiesFromQuery.getString("supported_values"));
				propertyRecord.setExample_value(propertiesFromQuery.getString("example_value"));
				propertyRecord.setIs_editable(propertiesFromQuery.getBoolean("is_editable"));
				propertyRecord.setDisplay_in_UI(propertiesFromQuery.getBoolean("display_in_UI"));
				propertyRecord.setBlank_values_allowed(propertiesFromQuery.getBoolean("blank_values_allowed"));
				propertyRecord.setRestart_required(propertiesFromQuery.getBoolean("restart_required"));
				propertyRecord.setDate_time_created(new DateTime(propertiesFromQuery.getTimestamp("date_time_created")));
				propertyRecord.setDate_time_modified(new DateTime(propertiesFromQuery.getTimestamp("date_time_modified")));
				propertyRecord.setLast_updated_by_user(propertiesFromQuery.getString("last_updated_by_user"));
				
				listOfProperties.add(propertyRecord);
			}

		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / processDetailedResultSet] Exception occured while parsing result set from mySQL table. Returning faiure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / processDetailedResultSet] Exception occured while parsing result set from mySQL table. Returning faiure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / processConciseResultSet]Stack trace", exc);
			return false;	
		}
		
		System.out.println("[ConfigManager / ConfigManager / processDetailedResultSet] Result set from MySQL processed successfully.. returning true...");
		slog.info("[ConfigManager / ConfigManager / processDetailedResultSet] Result set from MySQL processed successfully.. returning true...");
		return true;
	}
	
	/**
	 * Fetch properties from configuration table in MySQL DB
	 * <p>
	 * This method executes the select SQL statement against the backend database. 
	 * </p>
	 * @return true, if successful
	 */
	public static ResultSet runSelectSQLScript(Connection dbConn, String queryFetchProperties)
	{	
		
		ResultSet propertiesFromQuery = null;
		
		try
		{
			PreparedStatement FetchPropertiesFromMySQL = dbConn.prepareStatement(queryFetchProperties);
			propertiesFromQuery = FetchPropertiesFromMySQL.executeQuery();
			
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / runSelectSQLScript]SQL Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / runSelectSQLScript]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / runSelectSQLScript]Stack trace", exc);
			return null;
		}
		catch (Exception exc)
		{
			System.out.println("[ConfigManager / ConfigManager / runSelectSQLScript] Exception occured while Creating table. Returning faiure. Exception is - " + exc.getMessage());
			exc.printStackTrace();	
			slog.error("[ConfigManager / ConfigManager / runSelectSQLScript] Exception occured while Creating table. Returning faiure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / runSelectSQLScript]Stack trace", exc);
		}
		
		return propertiesFromQuery;
	}
	
	/**
	 * Take result set as returned by MySQL and format the result set to display on the command line
	 * @param rs
	 * @return true if successful
	 */
	public static boolean formatAndDisplayResultSet(ResultSet rs){
		
		try{
			if(null == rs || !rs.next()){
				System.out.println("[ConfigManager / ConfigManager / formatAndDisplayResultSet] No Existing properties to be fetched from the database");
				return true;
			}
			rs.beforeFirst();
			System.out.println("====================");
			System.out.println("   Adapters List    ");
			System.out.println("====================");
			while(rs.next()){
				String adapterName = rs.getString("adapter");
				System.out.println(adapterName);
			}
		}
		catch(Exception exc){
			System.out.println(" [ConfigManager / ConfigManager / formatAndDisplayResultSet]Error occurred while formatting SQL result set. Error message is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / formatAndDisplayResultSet]Error occurred while formatting SQL result set. Error message is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / formatAndDisplayResultSet]Stack trace", exc);
			return false;
		}
		return true;
	}
	
	/**
	 * Execute a MySQL query to fetch all adapters
	 * @return true if successful
	 */
	public static boolean getAllAdapters(){
		Connection connection = getConnection();
		if(null == connection){
			System.out.println("[ConfigManager / ConfigManager / getAllAdapters] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / getAllAdapters] Could not obtain the database connection. Returning");
			return false;
		}
		try{
			PreparedStatement sqlStmt = connection.prepareStatement(strSelectAdapters);
			ResultSet rs = sqlStmt.executeQuery();
			boolean bSuccess = formatAndDisplayResultSet(rs);
			if(false == bSuccess){
				System.out.println("Error occurred..");
				return false;
			}
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / getAllAdapters] Exception occured. Returning faiure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getAllAdapters] Exception occured. Returning faiure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getAllAdapters]Stack trace", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getAllAdapters] Exception occured. Returning faiure. Exception is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getAllAdapters] Exception occured. Returning faiure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / getAllAdapters]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(connection);
		}
		
		return true;
	}
	
	/**
	 * This method modifies the property value for properties whose dataType is "String"
	 * @param propertyName
	 * @param propertyValue
	 * @return true if successful
	 */
	public static boolean setPropertyValueForString(String propertyName, String propertyValue){
		
		try{
			boolean bSuccess = updateMySQLTable(propertyName, propertyValue, requestingUser);
			if(false == bSuccess){
				System.out.println("[ConfigManager / ConfigManager / setPropertyValueForString]  Unable to update mySQL table with the new property value, returning..");
				slog.info("[ConfigManager / ConfigManager / setPropertyValueForString]  Unable to update mySQL table with the new property value, returning..");
				return false;
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / setPropertyValueForString] Exception occured while setting property value as string or boolean.. Exception:"+exc.getMessage() );
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / setPropertyValueForString] Exception occured while setting property value as string or boolean.. Exception:"+exc.getMessage() );
			slog.error("[ConfigManager / ConfigManager / setPropertyValueForString]Stack trace", exc);
			return false;
		}
		System.out.println("[ConfigManager / ConfigManager / setPropertyValueForString] Property value modified successfully.. returning true...");
		slog.info("[ConfigManager / ConfigManager / setPropertyValueForString] Property value modified successfully.. returning true...");
		return true;
		
	}
	/**
	 * Validate the property values for datatypes integer and boolean
	 * @param dataType
	 * @param strValue
	 * @return true if valid
	 */
	private static boolean validateDataType(String dataType, String strValue){
		
		try{
			if(dataType.equalsIgnoreCase("Integer")){
				if(Integer.parseInt(strValue)%1 != 0 || Integer.parseInt(strValue)<0){
					System.out.println("[ConfigManager / ConfigManager / validateDataType] Invalid integer value.. Returning false..");
					slog.info("[ConfigManager / ConfigManager / validateDataType] Invalid integer value.. Returning false..");
					return false;
				}
			}
			else if(dataType.equalsIgnoreCase("Boolean")){
				if(null != strValue){
					return "true".equals(strValue) || "false".equals(strValue);
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / validateDataType] Invalid data type:"+dataType+" value.. Returning false..");
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateDataType] Invalid data type:"+dataType+" value.. Returning false..");
			slog.error("[ConfigManager / ConfigManager / validateDataType]Stack trace", exc);
			return false;
		}
		System.out.println("[ConfigManager / ConfigManager / validateDataType] valid data type.. returning true...");
		slog.info("[ConfigManager / ConfigManager / validateDataType] valid data type.. returning true...");
		return true;
	}
	
	/**
	 * Validate if the cron expression string is a valid one by using the quartz library utility
	 * 
	 * @param cronExpression
	 * @return true is valid
	 */
	private static boolean validateCronExpression(String cronExpression){
		
		boolean valid = false;
		try{
			valid = org.quartz.CronExpression.isValidExpression(cronExpression);
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / validateCronExpression] Invalid cron expression value.. Returning false..");
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateCronExpression] Invalid cron expression value.. Returning false..");
			slog.error("[ConfigManager / ConfigManager / validateCronExpression]Stack trace", exc);
			return false;
		}
		System.out.println("[ConfigManager / ConfigManager / validateCronExpression] valid cron expression.. returning true...");
		slog.info("[ConfigManager / ConfigManager / validateCronExpression] valid cron expression.. returning true...");
		return valid;
	}
	
	/**
	 * This method modifies properties whose data_type is "Password"
	 * This method updates both MySQL table and in memory PropertiesData map
	 * @param propertyName
	 * @param propertyValue
	 * @param requestingUser
	 * @param propertyRecord
	 * @return true if successful
	 */
	public static boolean setPropertyValueForPassword(String propertyName, String propertyValue, ConfigurationDTO propertyRecord){
		
		try{
			String encryptedToken = encryptDataPassword(propertyValue, Base64.decodeBase64(propertyRecord.getSalt_Value().getBytes()));
			boolean bSuccess = updateMySQLTable(propertyName, encryptedToken, requestingUser);
			if(false == bSuccess){
				System.out.println("[ConfigManager / ConfigManager / setPropertyValueForPassword]  Unable to update mySQL table with the new property value, returning..");
				slog.info("[ConfigManager / ConfigManager / setPropertyValueForPassword]  Unable to update mySQL table with the new property value, returning..");
				return false;
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / setPropertyValueForPassword] Exception occured while setting property value as password type.. Exception:"+exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / setPropertyValueForPassword] Exception occured while setting property value as password type.. Exception:"+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / setPropertyValueForPassword]Stack trace", exc);
			return false;
		}
		System.out.println("[ConfigManager / ConfigManager / setPropertyValueForPassword] Property value modified successfully.. returning true...");
		slog.info("[ConfigManager / ConfigManager / setPropertyValueForPassword] Property value modified successfully.. returning true...");
		return true;
		
	}

	
	/**
	 * This method updates MySQL table with the new property value
	 * @param propertyName
	 * @param propertyValue
	 * @param requestingUser
	 * @return true if successful
	 */
	public static boolean updateMySQLTable(String propertyName, String propertyValue, String requestingUser){
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / updateMySQLTable] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / updateMySQLTable] Could not obtain the database connection. Returning");
			return false;
		}
		try{
			PreparedStatement updateQuery = null;
			
			//Update statement
			String updateStmt = "UPDATE configuration SET value = ?, last_updated_by_user = ? WHERE name LIKE ?";
			
			updateQuery = dbConn.prepareStatement(updateStmt);
			updateQuery.setString(1, propertyValue);
			updateQuery.setString(2, requestingUser);
			updateQuery.setString(3, propertyName);
			
			updateQuery.executeUpdate();
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / updateMySQLTable] Exception occured while updating the property value in MySQL table.. Exception:"+exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / updateMySQLTable] Exception occured while updating the property value in MySQL table.. Exception:"+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / updateMySQLTable]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		System.out.println("[ConfigManager / ConfigManager / updateMySQLTable] Property value updated successfully in mySQL.. returning true...");
		slog.info("[ConfigManager / ConfigManager / updateMySQLTable] Property value updated successfully in mySQL.. returning true...");
		return true;
	}
	
	/**
	 * Check if the user entered value is one among the options in supported values for control_type "DropDown"
	 * @param supportedValues
	 * @param propertyValue
	 * @return true if successful
	 */
	public static boolean checkDropdownValue(String supportedValues, String propertyValue){
		
		try{
			List<String> supportedValuesList = Arrays.asList(supportedValues.split(","));
			boolean valid = false;
			for(String supportedVal : supportedValuesList){
				if(propertyValue.equalsIgnoreCase(supportedVal)){
					valid = true;
				}
			}
			if(true == valid){
				return true;
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / checkDropdownValue]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / checkDropdownValue]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / checkDropdownValue]Stack trace", exc);
		}
		
		return false;
	}
	
	/**
	 * Check if the region/view record already exists in region_views table
	 * @param regionViewName
	 * @return "new" or "existing" based on result
	 */
	public static String checkIfRegionAlreadyExists(String regionViewName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / checkIfRegionAlreadyExists] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / checkIfRegionAlreadyExists] Could not obtain the database connection. Returning");
			return null;
		}
		try{
			String strSelectRegion = "select * from region_views where name like '"+regionViewName+"'";
			ResultSet rs = runSelectSQLScript(dbConn, strSelectRegion);
			if(null == rs || !rs.next()){
				System.out.println("[Configuration / Config / checkIfRegionAlreadyExists] Region/View record does not exist to be fetched from the database");
				slog.info("[Configuration / Config / checkIfRegionAlreadyExists] Region/View record does not exist to be fetched from the database");
				return "New";
			}
			else{
				System.out.println("[Configuration / Config / checkIfRegionAlreadyExists] Region/View record already exists in the database");
				slog.info("[Configuration / Config / checkIfRegionAlreadyExists] Region/View record already exists in the database");
				return "Existing";
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / checkIfRegionAlreadyExists]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / checkIfRegionAlreadyExists]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / checkIfRegionAlreadyExists]Stack trace", exc);
			return null;
		}
		finally{
			closeConnection(dbConn);
		}
	}
	
	/**
	 * Check if the appliance record already exists in region_views table
	 * @param applianceName
	 * @return "new" or "existing" based on result
	 */
	public static String checkIfApplianceAlreadyExists(String applianceName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / checkIfApplianceAlreadyExists] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / checkIfApplianceAlreadyExists] Could not obtain the database connection. Returning");
			return null;
		}
		try{
			String strSelectRegion = "select * from appliance where fqdn like '"+applianceName+"'";
			ResultSet rs = runSelectSQLScript(dbConn, strSelectRegion);
			if(null == rs || !rs.next()){
				System.out.println("[Configuration / Config / checkIfApplianceAlreadyExists] Appliance record does not exist to be fetched from the database");
				slog.info("[Configuration / Config / checkIfApplianceAlreadyExists] Appliance record does not exist to be fetched from the database");
				return "New";
			}
			else{
				System.out.println("[Configuration / Config / checkIfApplianceAlreadyExists] Appliance record already exists in the database");
				slog.info("[Configuration / Config / checkIfApplianceAlreadyExists] Appliance record already exists in the database");
				return "Existing";
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / checkIfApplianceAlreadyExists]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / checkIfApplianceAlreadyExists]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / checkIfApplianceAlreadyExists]Stack trace", exc);
			return null;
		}
		finally{
			closeConnection(dbConn);
		}
	}
	
	public static boolean validateArgumentValues(String applianceCountry, String applianceRegion, String applianceType, String applianceIPAddress){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / validateArgumentValues] Could not obtain the database connection. Returning");
			return false;
		}
		try{
			//validate country code
			if(null != applianceCountry && false == applianceCountry.isEmpty()){
				if(applianceCountry.length() != 2){
					System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] Invalid country code.. Please enter a two character country code. Eg. US,CN,GE");
					slog.info("[ConfigManager / ConfigManager / validateArgumentValues] Invalid country code.. Please enter a two character country code. Eg. US,CN,GE");
					return false;
				}
			}
			
			//validate applianceType
			if(null != applianceType && false == applianceType.isEmpty()){
				List<String> applianceTypeList = Arrays.asList("AX","NX","EX","HX");
				if(!(applianceTypeList.contains(applianceType))){
					System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] Invalid appliance type.. Please enter one of these types - AX, NX, HX, EX");
					slog.info("[ConfigManager / ConfigManager / validateArgumentValues]Invalid appliance type.. Please enter one of these types - AX, NX, HX, EX");
					return false;
				}
			}
				
			//validate applianceRegion
			if(null != applianceRegion && false == applianceRegion.isEmpty()){
				String strSelectRegion = "select name from region_views";
				ResultSet rs = runSelectSQLScript(dbConn, strSelectRegion);
				if(null == rs || !rs.next()){
					System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] No Existing regions to be fetched from the database.. Add the new region before adding the appliance");
					slog.info("[ConfigManager / ConfigManager / validateArgumentValues] No Existing regions to be fetched from the database.. Add the new region before adding the appliance");
					return false;
				}
				rs.beforeFirst();
				List<String> regions = new ArrayList<String>();
				String regionsList = "";
				while(rs.next()){
					regions.add(rs.getString("name"));
					regionsList += rs.getString("name") + ",";
				}
				
				if(!(regions.contains(applianceRegion))){
					System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] Invalid region for the appliance.. Please enter one of the configured regions.."+regionsList);
					slog.info("[ConfigManager / ConfigManager / validateArgumentValues] Invalid region for the appliance.. Please enter one of the configured regions.."+regionsList);
					return false;
				}
			}
			
			//validate ipaddress
			if(null != applianceIPAddress && false == applianceIPAddress.isEmpty()){
				String IPADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
											"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
											"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
											"([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
				
				Pattern pattern =  Pattern.compile(IPADDRESS_PATTERN);
				Matcher matcher  = pattern.matcher(applianceIPAddress);
				if(!(matcher.matches())){
					System.out.println("[ConfigManager / ConfigManager / validateArgumentValues] Invalid IP address for the appliance.. Please enter a valid IP address");
					slog.info("[ConfigManager / ConfigManager / validateArgumentValues] Invalid IP address for the appliance.. Please enter a valid IP address");
					return false;
				}
			}
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / validateArgumentValues]SQL Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateArgumentValues]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateArgumentValues]Stack trace", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / validateArgumentValues]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateArgumentValues]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateArgumentValues]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Validate  the argument values passed by the user in command line and if valid, go ahead and add/modify the appliance record
	 * @param applianceSetName
	 * @param applianceType
	 * @param applianceRegion
	 * @param applianceCountry
	 * @param applianceIPAddress
	 * @param applianceUsername
	 * @param appliancePassword
	 * @param applianceVersion
	 * @return true if successfully added/modified appliance record
	 */
	public static boolean validateAndSetAppliance(String applianceName, String applianceType, String applianceRegion, String applianceCountry, String applianceIPAddress, String applianceUsername, String appliancePassword, String applianceVersion){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetAppliance] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / validateAndSetAppliance] Could not obtain the database connection. Returning");
			return false;
		}
		try{
			boolean bSuccess = validateArgumentValues(applianceCountry, applianceRegion, applianceType, applianceIPAddress);
			if(true == bSuccess){
				String status = checkIfApplianceAlreadyExists(applianceName);
				if(status.equalsIgnoreCase("Existing")){
					
					String existingApplType = null;
					String existingIPAddress = null;
					String existingApplRegion = null;
					String existingApplCountry = null;
					String existingApplUsername = null;
					String existingApplPassword = null;
					String existingSaltValue = null;
					String existingApplVersion = null;
					
					String strSelectAppliance = "select * from appliance where fqdn like '"+applianceName+"'";
					ResultSet rs = runSelectSQLScript(dbConn, strSelectAppliance);
					while(rs.next()){
						existingApplType = rs.getString("type");
						existingIPAddress = rs.getString("ip_address");
						existingApplRegion = rs.getString("region");
						existingApplCountry = rs.getString("country");
						existingApplUsername = rs.getString("username");
						existingApplPassword = rs.getString("password");
						existingSaltValue = rs.getString("salt_value");
						existingApplVersion = rs.getString("version");
					}
					
					String updateStmt = "UPDATE appliance SET ip_address = ?, region = ?, country = ?, type = ?,"
							+ "username = ?, password = ?, version = ?, date_time_modified = ?, last_updated_by_user = ? WHERE fqdn LIKE ?";
					
					PreparedStatement sqlStmt = dbConn.prepareStatement(updateStmt);
					if(null == applianceIPAddress){
						sqlStmt.setString(1, existingIPAddress);
					}
					else{
						sqlStmt.setString(1, applianceIPAddress);
					}
					
					if(null == applianceRegion){
						sqlStmt.setString(2, existingApplRegion);
					}
					else{
						sqlStmt.setString(2, applianceRegion);
					}
					
					if(null == applianceCountry){
						sqlStmt.setString(3, existingApplCountry);
					}
					else{
						sqlStmt.setString(3, applianceCountry);
					}
					
					if(null == applianceType){
						sqlStmt.setString(4, existingApplType);
					}
					else{
						sqlStmt.setString(4, applianceType);
					}
					
					if(null == applianceUsername){
						sqlStmt.setString(5, existingApplUsername);
					}
					else{
						sqlStmt.setString(5, applianceUsername);
					}
					
					if(null == appliancePassword){
						sqlStmt.setString(6, existingApplPassword);
					}
					else{
						sqlStmt.setString(6, encryptDataPassword(appliancePassword,Base64.decodeBase64(existingSaltValue.getBytes())));
					}
					
					if(null == applianceVersion){
						sqlStmt.setString(7, existingApplVersion);
					}
					else{
						sqlStmt.setString(7, applianceVersion);
					}
					
					sqlStmt.setTimestamp(8, new java.sql.Timestamp(new java.util.Date().getTime()));
					sqlStmt.setString(9, requestingUser);
					sqlStmt.setString(10, applianceName);
					
					sqlStmt.executeUpdate();
					
					
				}
				else if(status.equalsIgnoreCase("New")){
					String strInsertToApplianceTable = "INSERT INTO appliance(fqdn, ip_address, region, country, type, username, salt_value, password, version, date_time_created, date_time_modified, last_updated_by_user) "
							+ "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
					
					PreparedStatement sqlStmt = dbConn.prepareStatement(strInsertToApplianceTable);
					
					if(null == applianceName){
						sqlStmt.setString(1, "");
					}
					else{
						sqlStmt.setString(1, applianceName);
					}
					
					if(null == applianceIPAddress){
						sqlStmt.setString(2, "");
					}
					else{
						sqlStmt.setString(2, applianceIPAddress);
					}
					
					if(null == applianceRegion){
						sqlStmt.setString(3, "");
					}
					else{
						sqlStmt.setString(3, applianceRegion);
					}
					
					if(null == applianceCountry){
						sqlStmt.setString(4, "");
					}
					else{
						sqlStmt.setString(4, applianceCountry);
					}
					
					if(null == applianceType){
						sqlStmt.setString(5, "");
					}
					else{
						sqlStmt.setString(5, applianceType);
					}
					
					if(null == applianceUsername){
						sqlStmt.setString(6, "");
					}
					else{
						sqlStmt.setString(6, applianceUsername);
					}
						
					byte[] saltValue = getRandomSalt();
					sqlStmt.setString(7, new String(Base64.encodeBase64(saltValue)));
					
					if(null != appliancePassword && false == appliancePassword.isEmpty()){
						sqlStmt.setString(8, encryptDataPassword(appliancePassword,saltValue));
					}
					else{
						sqlStmt.setString(8, "");
					}
					
					if(null == applianceVersion){
						sqlStmt.setString(9, "");
					}
					else{
						sqlStmt.setString(9, applianceVersion);
					}
					
					sqlStmt.setTimestamp(10, new java.sql.Timestamp(new java.util.Date().getTime()));
					sqlStmt.setTimestamp(11, new java.sql.Timestamp(new java.util.Date().getTime()));
					sqlStmt.setString(12, requestingUser);
					sqlStmt.executeUpdate();
				}
			} 
			else
				return false;
			
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetAppliance]SQL Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateAndSetAppliance]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateAndSetAppliance]Stack trace", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetAppliance]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateAndSetAppliance]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateAndSetAppliance]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Validate  the argument values passed by the user in command line and if valid, go ahead and add/modify the regionView record
	 * @param regionViewName
	 * @param readableName
	 * @param viewType
	 * @param domainValue
	 * @return true if successfully added/modified region/view record
	 */
	public static boolean validateAndSetRegionView(String regionViewName, String readableName, String viewType, String domainValue){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetRegionView] Could not obtain the database connection. Returning");
			slog.info("[ConfigManager / ConfigManager / validateAndSetRegionView] Could not obtain the database connection. Returning");
			return false;
		}
		try{
			String status = checkIfRegionAlreadyExists(regionViewName);
			if(status.equalsIgnoreCase("Existing")){
				String existingReadableName = null;
				String existingValue = null;
				
				String strSelectRegion = "select * from region_views where name like '"+regionViewName+"'";
				ResultSet rs = runSelectSQLScript(dbConn, strSelectRegion);
				while(rs.next()){
					existingReadableName = rs.getString("readable_name");
					existingValue = rs.getString("value");
				}
				
				String updateQuery = "UPDATE region_views SET readable_name = ?, type = ?, value = ?, date_time_modified = ?, last_updated_by_user = ? WHERE name LIKE ?";
				
				PreparedStatement updateStmt = dbConn.prepareStatement(updateQuery);
				if(null != readableName){
					updateStmt.setString(1, readableName);
				}
				else{
					updateStmt.setString(1, existingReadableName);
				}
				
				updateStmt.setString(2, viewType);
				
				if(null == domainValue){
					updateStmt.setString(3, existingValue);
				}
				else{
					updateStmt.setString(3, domainValue);
				}
				
				updateStmt.setTimestamp(4, new java.sql.Timestamp(new java.util.Date().getTime()));
				updateStmt.setString(5,requestingUser);
				updateStmt.setString(6, regionViewName);
				
				updateStmt.executeUpdate();
			}
			else if(status.equalsIgnoreCase("New")){
				String strInsertToRegionTable = "INSERT INTO region_views(name, readable_name, type, value, date_time_created, date_time_modified, last_updated_by_user)"
						+ " VALUES (?,?,?,?,?,?,?)";
				
				PreparedStatement sqlStmt = dbConn.prepareStatement(strInsertToRegionTable);
				sqlStmt.setString(1, regionViewName);
				sqlStmt.setString(2, readableName);
				sqlStmt.setString(3, viewType);
				if(null == domainValue){
					sqlStmt.setString(4, "");
				}
				else{
					sqlStmt.setString(4, domainValue);
				}
				sqlStmt.setTimestamp(5, new java.sql.Timestamp(new java.util.Date().getTime()));
				sqlStmt.setTimestamp(6, new java.sql.Timestamp(new java.util.Date().getTime()));
				sqlStmt.setString(7, requestingUser);
				
				sqlStmt.executeUpdate();		
			}
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetRegionView]SQL Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateAndSetRegionView]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateAndSetRegionView]Stack trace", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / validateAndSetRegionView]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / validateAndSetRegionView]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / validateAndSetRegionView]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Validate  the argument values passed by the user in command line and if valid, go ahead and set the property value
	 * @param propertyName
	 * @param propertyValue
	 * @return true if successful
	 */
	public static boolean validateAndSetPropertyValue(String propertyName, String propertyValue){
		
		try{
			boolean bSuccess;
			List<ConfigurationDTO> propertyDetailsList = getPropertyDetailsForPropertyName(propertyName);
			if(!propertyDetailsList.isEmpty() && null!=propertyDetailsList){
				Iterator<ConfigurationDTO> propertyDetails = propertyDetailsList.iterator();
				while (propertyDetails.hasNext()) {
					ConfigurationDTO propertyRecord = propertyDetails.next();
					if(propertyRecord.getControl_type().equalsIgnoreCase("DropDown")){
						bSuccess = checkDropdownValue(propertyRecord.getSupported_values(),propertyValue);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Invalid value for dropdown control type.."
									+ "Choose from the list of suported file formats.. Returning false..");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Invalid value for dropdown control type.."
									+ "Choose from the list of suported file formats.. Returning false..");
							return false;
						}
					}
					
					String dataType = propertyRecord.getData_type();
					if(dataType.equalsIgnoreCase("String") || dataType.equalsIgnoreCase("Integer") || dataType.equalsIgnoreCase("Boolean") ){
						bSuccess = validateDataType(dataType, propertyValue);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Invalid data type.. Returning false..");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Invalid data type.. Returning false..");
							return false;
						}
						bSuccess = setPropertyValueForString(propertyName, propertyValue);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as string type");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as string type");
							return false;
						}
					}
					else if(dataType.equalsIgnoreCase("CronSchedule")){
						bSuccess = validateCronExpression(propertyValue);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Invalid cron expression for property:"+propertyName+". Returning false");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Invalid cron expression for property:"+propertyName+". Returning false");
							return false;
						}
						bSuccess = setPropertyValueForString(propertyName, propertyValue);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as cron expression type");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as cron expression type");
							return false;
						}
					}
					else if(dataType.equalsIgnoreCase("Password")){
						bSuccess = setPropertyValueForPassword(propertyName, propertyValue, propertyRecord);
						if(false == bSuccess){
							System.out.println("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as password type");
							slog.info("[ConfigManager / ConfigManager / setPropertyValue] Unable to update property value as password type");
							return false;
						}
					}
					else if(dataType.equalsIgnoreCase("FileUpload")){
						System.out.println("[ConfigManager / ConfigManager / setPropertyValue]Cannot set value for 'FileUpload' data type..Returning failure..");
						slog.info("[ConfigManager / ConfigManager / setPropertyValue]Cannot set value for 'FileUpload' data type..Returning failure..");
						return false;
					}
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / setPropertyValue]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / setPropertyValue]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / setPropertyValue]Stack trace", exc);
			return false;
		}
		
		return true;
	}
	
	/**
	 * Converts date/time in the {@code java.util.Date} object to a {@code String} in ISO-8601 format.
	 * <p>
	 * This method assumes the passed {@code java.util.Date} object contains the date/time in UTC time zone
	 * It then converts it to a string in ISO-8601 compliant format which is 'yyyy-MM-dd'T'HH:mmssZ'
	 * e.g. 2013-10-28T13:21:01Z
	 *    
	 * @param dtTimeInUTC  the date/time {@code java.util.Date} object to be converted, null returns null 
	 *   
	 * @return date/time in ISO-8601 compliant format, if successful, null otherwise
	 */
	private static String convertDateTimeToISO8601StringinUTCTimeZone(Date dtTime)
	{
		if (null == dtTime)
		{
			System.out.println("[ConfigManager / ConfigManager / convertDateTimeToISO8601StringinUTCTimeZone] "
					+ "The date/time object cannot be null. Returning failure");
			slog.info("[ConfigManager / ConfigManager / convertDateTimeToISO8601StringinUTCTimeZone] "
					+ "The date/time object cannot be null. Returning failure");
			return null;
		}
		
		DateTime dtTimeObj = new DateTime(dtTime.getTime());
		String strDateTimeInUTC;
		DateTimeFormatter isoDtTimeFormatter = ISODateTimeFormat.dateTimeNoMillis();
		strDateTimeInUTC = isoDtTimeFormatter.withZoneUTC().print(dtTimeObj);

		return strDateTimeInUTC;		
	}
	
	/**
	 * create a JSONObject of ConfigurationDTO type
	 * @param propertyDetails
	 * @param propertyRecord
	 * @return JSONObject of ConfigurationDTO type
	 */
	private static JSONObject fillPropertyObject(JSONObject propertyDetails, ConfigurationDTO propertyRecord){
		
		try{
			propertyDetails.put("name", propertyRecord.getName());
			propertyDetails.put("displayName", propertyRecord.getDisplay_name());
			propertyDetails.put("sequence", propertyRecord.getSequence());
			propertyDetails.put("description", propertyRecord.getDescription());
			propertyDetails.put("toolTip", propertyRecord.getTool_tip());
			propertyDetails.put("controlType", propertyRecord.getControl_type());
			propertyDetails.put("dataType", propertyRecord.getData_type());
			
			if(propertyRecord.getData_type().equalsIgnoreCase("Boolean")){
				if(propertyRecord.getValue().equalsIgnoreCase("true")){
					propertyDetails.put("value", true);
				}
				else if(propertyRecord.getValue().equalsIgnoreCase("false")){
					propertyDetails.put("value", false);
				}
			}
			else if(propertyRecord.getControl_type().equalsIgnoreCase("PasswordTextBox")){
				propertyDetails.put("value", "********");
			}
			else{
				propertyDetails.put("value", propertyRecord.getValue());
			}
			
			propertyDetails.put("saltValue", propertyRecord.getSalt_Value());
			propertyDetails.put("uploadDirectory", propertyRecord.getUpload_directory());
			propertyDetails.put("uploadFileName", propertyRecord.getUpload_File_Name());
			propertyDetails.put("upload_file_type_URI", propertyRecord.getUpload_File_Type_URI());
			propertyDetails.put("supportedFileFormats", propertyRecord.getSupported_file_formats());
			propertyDetails.put("maxUploadFileSize", propertyRecord.getMax_upload_file_size());
			propertyDetails.put("uploadDirectory", propertyRecord.getUpload_directory());
			propertyDetails.put("supportedValues", propertyRecord.getSupported_values());
			propertyDetails.put("exampleValue", propertyRecord.getExample_value());
			propertyDetails.put("isEditable", propertyRecord.isIs_editable());
			propertyDetails.put("displayInUI", propertyRecord.isDisplay_in_UI());
			propertyDetails.put("blankValuesAllowed", propertyRecord.isBlank_values_allowed());
			propertyDetails.put("restartRequired", propertyRecord.isRestart_required());
			propertyDetails.put("dateTimeCreated", convertDateTimeToISO8601StringinUTCTimeZone(propertyRecord.getDate_time_created().toDate()));
			propertyDetails.put("dateTimeLastModified", convertDateTimeToISO8601StringinUTCTimeZone(propertyRecord.getDate_time_modified().toDate()));
			propertyDetails.put("lastUpdatedByUser", propertyRecord.getLast_updated_by_user());
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / fillPropertyObject]  Error occured while filling the DTO Property object:"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / fillPropertyObject]  Error occured while filling the DTO Property object:"+exc);
			slog.error("[ConfigManager / ConfigManager / fillPropertyObject]Stack trace", exc);
			return null;
		}
		
		return propertyDetails;
	}
	
	/**
	 * Format the response object from MySQL into a JSON string
	 * @param propertyList
	 * @return formatted string  in json format if successful
	 */
	private static String convertPropertiesListToJSONObject(List<ConfigurationDTO> propertyList){
		
		try{
			JSONArray adapterSectionsList = new JSONArray();
			
			Iterator<ConfigurationDTO> propertiesFromMySQLIterator = propertyList.iterator();
			while (propertiesFromMySQLIterator.hasNext()) {
				ConfigurationDTO propertyRecord = propertiesFromMySQLIterator.next();
				
				JSONObject propertyDetails = new JSONObject();
				propertyDetails = fillPropertyObject(propertyDetails, propertyRecord);
				
				JSONObject sectionPropertyDetails = new JSONObject();
				JSONArray sectionPropertyDetailsList = new JSONArray();
				
				boolean newAdapterFound = true;
				for(int indexA=0; indexA<adapterSectionsList.length(); indexA++){
					JSONObject adapterSections = new JSONObject();
					adapterSections = adapterSectionsList.getJSONObject(indexA);
					
					if(adapterSections.get("AdapterName").toString().equalsIgnoreCase(propertyRecord.getAdapter())){
						newAdapterFound = false;
						sectionPropertyDetailsList = (JSONArray)adapterSections.get("SectionDetailsList");
						
						boolean newSectionFound = true;
						for(int indexB=0; indexB<sectionPropertyDetailsList.length(); indexB++){
							sectionPropertyDetails = sectionPropertyDetailsList.getJSONObject(indexB);
							
							if(sectionPropertyDetails.get("SectionName").toString().equalsIgnoreCase(propertyRecord.getSection())){
								newSectionFound = false;
								
								JSONObject property = new JSONObject();
								property.put("PropertyDetails", propertyDetails);
								JSONArray propertiesList = (JSONArray)sectionPropertyDetails.get("PropertyDetailsList");
								propertiesList.put(property);
								
								sectionPropertyDetails.put("PropertyDetailsList", propertiesList);
							}
						}
						
						if(true == newSectionFound){
							
							JSONObject property = new JSONObject();
							property.put("PropertyDetails", propertyDetails);
							JSONArray propertiesList = new JSONArray();
							propertiesList.put(property);
							
							sectionPropertyDetails = new JSONObject();
							sectionPropertyDetails.put("SectionName", propertyRecord.getSection());
							sectionPropertyDetails.put("PropertyDetailsList", propertiesList);
							
							sectionPropertyDetailsList.put(sectionPropertyDetails);
						}
					}
				}
				if(true == newAdapterFound){
					JSONObject property = new JSONObject();
					property.put("PropertyDetails", propertyDetails);
					JSONArray propertiesList = new JSONArray();
					propertiesList.put(property);
					
					sectionPropertyDetails = new JSONObject();
					sectionPropertyDetails.put("SectionName", propertyRecord.getSection());
					sectionPropertyDetails.put("PropertyDetailsList", propertiesList);
					
					sectionPropertyDetailsList = new JSONArray();
					sectionPropertyDetailsList.put(sectionPropertyDetails);
					
					JSONObject adapter = new JSONObject();
					adapter.put("AdapterName", propertyRecord.getAdapter());
					adapter.put("SectionDetailsList", sectionPropertyDetailsList);
					
					adapterSectionsList.put(adapter);
				}
				
			}
			
			if(null != adapterSectionsList){
				JSONObject propertiesJSON = new JSONObject();
				propertiesJSON.put("DetailedProperties", adapterSectionsList);
				return propertiesJSON.toString();
			}
			
			
		}catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / convertPropertiesListToJSONObject] "
					+ "Error occured while parsing mySQL resultset. Error is:"+ exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / convertPropertiesListToJSONObject] "
					+ "Error occured while parsing mySQL resultset. Error is:"+ exc);
			slog.error("[ConfigManager / ConfigManager / convertPropertiesListToJSONObject]Stack trace", exc);
		}
		return null;
	}
	
	/**
	 * Fetch all properties in Configuration table in MySQL database
	 * @param outputFormat
	 * @return true if successful
	 */
	public static boolean getAllProperties(String outputFormat){
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			ResultSet propertiesFromQuery = null;
			if(outputFormat.equalsIgnoreCase("concise")){
				String fetchAllPropsConcise = "SELECT name,value,display_name,adapter,control_type FROM configuration";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsConcise);
				if(null != propertiesFromQuery){
					String formattedStr = processConciseResultSet(propertiesFromQuery);
					if(false == formattedStr.isEmpty() && null != formattedStr){
						Gson gson = new GsonBuilder().setPrettyPrinting().create();
						JsonParser jp = new JsonParser();
						JsonElement je = jp.parse(formattedStr);
						String prettyJsonString = gson.toJson(je);
						
						System.out.println("=========================================================");
						System.out.println("                   Properties JSON:                      ");
						System.out.println("=========================================================");
						System.out.println(prettyJsonString);
						System.out.println("=========================================================");
					}
				}
			}
			else if(outputFormat.equalsIgnoreCase("detailed")){
				List<ConfigurationDTO> listOfProperties = new ArrayList<ConfigurationDTO>();
				String fetchAllPropsDetailed = "SELECT * FROM configuration";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsDetailed);
				if(null != propertiesFromQuery){
					boolean bSuccess = processDetailedResultSet(propertiesFromQuery, listOfProperties);
					if(true == bSuccess){
						if(!listOfProperties.isEmpty()){
							String propertiesJSON = convertPropertiesListToJSONObject(listOfProperties);
							Gson gson = new GsonBuilder().setPrettyPrinting().create();
							JsonParser jp = new JsonParser();
							JsonElement je = jp.parse(propertiesJSON);
							String prettyJsonString = gson.toJson(je);
							
							System.out.println("=========================================================");
							System.out.println("                   Properties JSON:                      ");
							System.out.println("=========================================================");
							System.out.println(prettyJsonString);
							System.out.println("=========================================================");
						}
					}
				}
			}
			
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getAllProperties] Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getAllProperties] Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getAllProperties]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Fetch all properties for a given adapter in Configuration table in MySQL database
	 * @param outputFormat
	 * @param adapterName
	 * @return true if successful
	 */
	public static boolean getAllPropertiesForAdapter(String outputFormat, String adapterName){
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			ResultSet propertiesFromQuery = null;
			if(outputFormat.equalsIgnoreCase("concise")){
				String fetchAllPropsConcise = "SELECT name,value,display_name,adapter,control_type FROM configuration where adapter like '"+adapterName+"'";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsConcise);
				if(null != propertiesFromQuery){
					String formattedStr = processConciseResultSet(propertiesFromQuery);
					if(false == formattedStr.isEmpty() && null != formattedStr){
						Gson gson = new GsonBuilder().setPrettyPrinting().create();
						JsonParser jp = new JsonParser();
						JsonElement je = jp.parse(formattedStr);
						String prettyJsonString = gson.toJson(je);
						
						System.out.println("=================================================================================");
						System.out.println("                   Properties JSON for Adapter:"+adapterName+"                   ");
						System.out.println("=================================================================================");
						System.out.println(prettyJsonString);
						System.out.println("=================================================================================");
					}
				}
			}
			else if(outputFormat.equalsIgnoreCase("detailed")){
				List<ConfigurationDTO> listOfProperties = new ArrayList<ConfigurationDTO>();
				String fetchAllPropsDetailed = "SELECT * FROM configuration where adapter like '"+adapterName+"'";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsDetailed);
				if(null != propertiesFromQuery){
					boolean bSuccess = processDetailedResultSet(propertiesFromQuery, listOfProperties);
					if(true == bSuccess){
						if(!listOfProperties.isEmpty()){
							String propertiesJSON = convertPropertiesListToJSONObject(listOfProperties);
							Gson gson = new GsonBuilder().setPrettyPrinting().create();
							JsonParser jp = new JsonParser();
							JsonElement je = jp.parse(propertiesJSON);
							String prettyJsonString = gson.toJson(je);
							
							System.out.println("====================================================================================");
							System.out.println("                   Properties JSON for Adapter:"+adapterName+"                      ");
							System.out.println("====================================================================================");
							System.out.println(prettyJsonString);
							System.out.println("====================================================================================");
						}
					}
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getAllPropertiesForAdapter]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getAllPropertiesForAdapter]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getAllPropertiesForAdapter]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		
		return true;
	}
	
	/**
	 * Fetch the region/view details of the specified region/view name
	 * @param regionViewName
	 * @return true if successful
	 */
	public static boolean getRegionViewDetails(String regionViewName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			ResultSet regionViewDetailsRS = null;
			
			String fetchAllDetails = "SELECT * FROM region_views where name like '"+regionViewName+"'";
			regionViewDetailsRS = runSelectSQLScript(dbConn, fetchAllDetails);
			if(null != regionViewDetailsRS){
				JSONObject regionViewDetails = new JSONObject();
				while(regionViewDetailsRS.next()){
					regionViewDetails.put("Region/View Name", regionViewDetailsRS.getString("name"));
					regionViewDetails.put("Readable Name", regionViewDetailsRS.getString("readable_name"));
					regionViewDetails.put("View Type", regionViewDetailsRS.getString("type"));
					regionViewDetails.put("Value", regionViewDetailsRS.getString("value"));
					regionViewDetails.put("Date Time Created", regionViewDetailsRS.getTimestamp("date_time_created"));
					regionViewDetails.put("Date Time Modified", regionViewDetailsRS.getTimestamp("date_time_modified"));
					regionViewDetails.put("Last Updated By User", regionViewDetailsRS.getString("last_updated_by_user"));
				}
				
				
				if(false == regionViewDetails.toString().isEmpty() && null != regionViewDetails.toString()){
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					JsonParser jp = new JsonParser();
					JsonElement je = jp.parse(regionViewDetails.toString());
					String prettyJsonString = gson.toJson(je);
					
					System.out.println("=================================================================================");
					System.out.println("                Region/View Details for:"+regionViewName+"                   ");
					System.out.println("=================================================================================");
					System.out.println(prettyJsonString);
					System.out.println("=================================================================================");
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getRegionViewDetails]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getRegionViewDetails]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getRegionViewDetails]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Fetch the appliance details of the specified appliance host name
	 * @param applianceName
	 * @return true if successful
	 */
	public static boolean getApplianceDetails(String applianceName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			ResultSet applianceDetailsRS = null;
			
			String fetchAllDetails = "SELECT * FROM appliance where fqdn like '"+applianceName+"'";
			applianceDetailsRS = runSelectSQLScript(dbConn, fetchAllDetails);
			if(null != applianceDetailsRS){
				JSONObject applDetails = new JSONObject();
				while(applianceDetailsRS.next()){
					applDetails.put("Appliance Name/FQDN", applianceDetailsRS.getString("fqdn"));
					applDetails.put("IP Address", applianceDetailsRS.getString("ip_address"));
					applDetails.put("Region", applianceDetailsRS.getString("region"));
					applDetails.put("Country", applianceDetailsRS.getString("country"));
					applDetails.put("Appliance Type", applianceDetailsRS.getString("type"));
					applDetails.put("Username", applianceDetailsRS.getString("username"));
					applDetails.put("Date Time Last Seen", applianceDetailsRS.getTimestamp("date_time_last_seen"));
					applDetails.put("Version", applianceDetailsRS.getString("version"));
					applDetails.put("Status", applianceDetailsRS.getString("status"));
					applDetails.put("Date Time Created", applianceDetailsRS.getTimestamp("date_time_created"));
					applDetails.put("Date Time Modified", applianceDetailsRS.getTimestamp("date_time_modified"));
					applDetails.put("Last Updated By User", applianceDetailsRS.getString("last_updated_by_user"));
				}
				
				
				if(false == applDetails.toString().isEmpty() && null != applDetails.toString()){
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					JsonParser jp = new JsonParser();
					JsonElement je = jp.parse(applDetails.toString());
					String prettyJsonString = gson.toJson(je);
					
					System.out.println("=================================================================================");
					System.out.println("                Appliance Details for:"+applianceName+"                   ");
					System.out.println("=================================================================================");
					System.out.println(prettyJsonString);
					System.out.println("=================================================================================");
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getApplianceDetails]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getApplianceDetails]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getApplianceDetails]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Remove the region entry in appliance table if user deletes any of the regions from region_views table
	 * @param regionViewName
	 * @return true if successful
	 */
	private static boolean removeRegionFromApplianceRecords(String regionViewName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] Could not obtain DB connection");
			slog.info("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] Could not obtain DB connection");
			return false;
		}
		try{
			String strSelectQuery = "SELECT appliance_id, fqdn, region FROM appliance where region like '%"+regionViewName+"%'";
			ResultSet applianceSet = runSelectSQLScript(dbConn, strSelectQuery);
			if(null == applianceSet || !applianceSet.next()){
				System.out.println("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] No Existing properties to be fetched from the database");
				slog.info("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] No Existing properties to be fetched from the database");
				return true;
			}
			
			applianceSet.beforeFirst();
			while(applianceSet.next()){
				/*List<String> newRegions = new ArrayList<String>();
				List<String> regions = Arrays.asList(applianceSet.getString("region").split(","));
				for(int arrIndex=0;arrIndex<regions.size();arrIndex++){
					if(!(regions.get(arrIndex).equalsIgnoreCase(regionViewName))){
						newRegions.add(regions.get(arrIndex));
					}
				}
				
				//concatenate regions string not required testing ConfigVersion1 branch, testing two branch switching
				String newRegionStr = "";
				for(int arrIndex=0;arrIndex<newRegions.size();arrIndex++){
					newRegionStr += newRegions.get(arrIndex) + ",";
				}
				
				int index = newRegionStr.lastIndexOf(",");
        		if(index == newRegionStr.length() - 1){
        			newRegionStr = newRegionStr.substring(0,index);
        		}*/
				
				//update appliance record with new region string
        		String updateStmt = "UPDATE appliance SET region = ?, date_time_modified = ?, last_updated_by_user = ? WHERE appliance_id LIKE ?";
    			
        		PreparedStatement updateQuery = dbConn.prepareStatement(updateStmt);
    			updateQuery.setString(1, null);
    			updateQuery.setTimestamp(2, new java.sql.Timestamp(new java.util.Date().getTime()));
    			updateQuery.setString(3, requestingUser);
    			updateQuery.setInt(4, applianceSet.getInt("appliance_id"));
    			updateQuery.executeUpdate();
			}
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] Exception occured while removing region from appliace records in table. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords]  Stack trace is:", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords] Exception occurred.....");
			slog.error("[ConfigManager / ConfigManager / removeRegionFromApplianceRecords]Stack trace:", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Delete the region/view record of the specified name
	 * @param regionViewName
	 * @return true if successful
	 */
	public static boolean deleteRegionView(String regionViewName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			String strDeleteRegionRecord = "DELETE FROM region_views where name like '"+regionViewName+"'";
			
			PreparedStatement sqlStmt = dbConn.prepareStatement(strDeleteRegionRecord);
			sqlStmt.executeUpdate();
			
			System.out.println("[ConfigManager / ConfigManager / deleteRegionView]Region/View deleted successfully..");
			slog.info("[ConfigManager / ConfigManager / deleteRegionView]Region/View deleted successfully..");
			
			boolean bSuccess = removeRegionFromApplianceRecords(regionViewName);
			if(false == bSuccess){
				System.out.println("[ConfigManager / ConfigManager / deleteRegionView] Error occurred while trying to remove region from appliance records.. Returning false..");
				slog.info("[ConfigManager / ConfigManager / deleteRegionView] Error occurred while trying to remove region from appliance records.. Returning false..");
				return false;
			}
			
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / deleteRegionView]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / deleteRegionView] Exception occured while deleting region/view record from table. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / deleteRegionView] Stack trace is:", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / deleteRegionView]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / deleteRegionView]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / deleteRegionView]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Delete the appliance record of the specified appliance host name
	 * @param applianceName
	 * @return true if successful
	 */
	public static boolean deleteAppliance(String applianceName){
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			String strDeleteApplianceRecord = "DELETE FROM appliance where fqdn like '"+applianceName+"'";
			
			PreparedStatement sqlStmt = dbConn.prepareStatement(strDeleteApplianceRecord);
			sqlStmt.executeUpdate();
			System.out.println("[ConfigManager / ConfigManager / deleteAppliance]Appliance record deleted successfully..");
			slog.info("[ConfigManager / ConfigManager / deleteAppliance]Appliance record deleted successfully..");
		}
		catch(SQLException exc){
			System.out.println("[ConfigManager / ConfigManager / deleteAppliance]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / deleteAppliance] Exception occured while deleting appliance record from table. Returning failure. Exception is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / deleteAppliance] Stack trace is:", exc);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / deleteAppliance]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / deleteAppliance]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / deleteAppliance]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		return true;
	}
	
	/**
	 * Fetch all property details for a given adapter and given property name in Configuration table in MySQL database
	 * @param outputFormat
	 * @param adapterName
	 * @return true if successful
	 */
	public static boolean getPropertyDetailsForProperty(String outputFormat, String adapterName, String propertyName){
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			return false;
		}
		try{
			ResultSet propertiesFromQuery = null;
			if(outputFormat.equalsIgnoreCase("concise")){
				String fetchAllPropsConcise = "SELECT name,value,display_name,adapter,control_type FROM configuration where "
						+ "adapter like '"+adapterName+"' and name like '"+propertyName+"'";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsConcise);
				if(null != propertiesFromQuery){
					String formattedStr = processConciseResultSet(propertiesFromQuery);
					if(false == formattedStr.isEmpty() && null != formattedStr){
						Gson gson = new GsonBuilder().setPrettyPrinting().create();
						JsonParser jp = new JsonParser();
						JsonElement je = jp.parse(formattedStr);
						String prettyJsonString = gson.toJson(je);
						
						System.out.println("=================================================================================");
						System.out.println("                Property Details for Property:"+propertyName+"                   ");
						System.out.println("=================================================================================");
						System.out.println(prettyJsonString);
						System.out.println("=================================================================================");
					}
				}
			}
			else if(outputFormat.equalsIgnoreCase("detailed")){
				List<ConfigurationDTO> listOfProperties = new ArrayList<ConfigurationDTO>();
				String fetchAllPropsDetailed = "SELECT * FROM configuration where "
						+ "adapter like '"+adapterName+"' and name like '"+propertyName+"'";
				propertiesFromQuery = runSelectSQLScript(dbConn, fetchAllPropsDetailed);
				if(null != propertiesFromQuery){
					boolean bSuccess = processDetailedResultSet(propertiesFromQuery, listOfProperties);
					if(true == bSuccess){
						if(!listOfProperties.isEmpty()){
							String propertiesJSON = convertPropertiesListToJSONObject(listOfProperties);
							Gson gson = new GsonBuilder().setPrettyPrinting().create();
							JsonParser jp = new JsonParser();
							JsonElement je = jp.parse(propertiesJSON);
							String prettyJsonString = gson.toJson(je);
							
							System.out.println("====================================================================================");
							System.out.println("                   Property Details for Property:"+propertyName+"                   ");
							System.out.println("====================================================================================");
							System.out.println(prettyJsonString);
							System.out.println("====================================================================================");
						}
					}
				}
			}
			
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getPropertyDetailsForProperty]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getPropertyDetailsForProperty]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getPropertyDetailsForProperty]Stack trace", exc);
			return false;
		}
		finally{
			closeConnection(dbConn);
		}
		
		return true;
	}
	/**
	 * Fetch properties from Configuration table in MySQL database based on the arguments passed by the user
	 * @param outputFormat
	 * @param adapterName
	 * @return true if successful
	 */
	public static boolean getProperties(String outputFormat, String adapterName, String propertyName){
		
		try{
			boolean bSuccess = false;
			if(adapterName.equalsIgnoreCase("all")){
				//fetch all properties from database based on output format
				bSuccess = getAllProperties(outputFormat);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / getProperties]Cannot get all properties...Returning failure..");
					slog.info("[ConfigManager / ConfigManager / getProperties]Cannot get all properties...Returning failure..");
					return false;
				}
			}
			else if(propertyName.equalsIgnoreCase("all")){
				//fetch all properties for this adapter from database based on output format
				bSuccess = getAllPropertiesForAdapter(outputFormat, adapterName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / getProperties]Cannot get properties for this adapter...Returning failure..");
					slog.info("[ConfigManager / ConfigManager / getProperties]Cannot get properties for this adapter...Returning failure..");
					return false;
				}
			}
			else{
				//fetch property details for this propertyName from database based on output format
				bSuccess = getPropertyDetailsForProperty(outputFormat, adapterName, propertyName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / getProperties]Cannot get property details for this property...Returning failure..");
					slog.info("[ConfigManager / ConfigManager / getProperties]Cannot get property details for this property...Returning failure..");
					return false;
				}
			}
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / getProperties]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / getProperties]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / getProperties]Stack trace", exc);
			return false;
		}
		
		return true;
	}
	
	/**
	 * Check if the user executing this utility has permissions to write to the log file directory.
	 * If yes, proceed to execute the command, else return
	 * @return true if successful
	 */
	public static boolean checkPermissionForLogFile(){
		
		BufferedWriter bw = null;
		FileWriter fw = null;
		
		try{
			File logFile =  new File("/usr/share/tomcat/logs/ConfigManager.log");
			if(!logFile.exists()){
				logFile.createNewFile();
			}
			
			fw = new FileWriter(logFile.getAbsoluteFile(), true);
			bw = new BufferedWriter(fw);
			
			bw.write("");

		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / checkPermissionForLogFile]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / checkPermissionForLogFile]Exception occurred..Exception-"+exc);
			slog.error("[ConfigManager / ConfigManager / checkPermissionForLogFile]Stack trace", exc);
			return false;
		}
		finally {

			try {

				if (bw != null)
					bw.close();

				if (fw != null)
					fw.close();

			} catch (IOException exc) {
				System.out.println("[ConfigManager / ConfigManager / checkPermissionForLogFile]Exception occurred..Exception-"+exc);
				exc.printStackTrace();
				slog.error("[ConfigManager / ConfigManager / checkPermissionForLogFile]Exception occurred..Exception-"+exc);
				slog.error("[ConfigManager / ConfigManager / checkPermissionForLogFile]Stack trace", exc);
			}
		}
		
		return true;
	}
	
	/**
	 * Function that takes care of executing alias creation script along with preparing the supporting config  files
	 * @return true if successful
	 */
	private static boolean executeDashboardAliasScript(){
		boolean bSuccess = false;
		try{
			bSuccess = prepareRegionConfigFile();
			if(false == bSuccess){
				System.out.println("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt prepare region config file.. Returning..");
				slog.info("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt prepare region config file.. Returning..");
				return false;
			}
			else{
				bSuccess = prepareDomainConfigFile();
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt prepare domain config file.. Returning..");
					slog.info("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt prepare domain config file.. Returning..");
					return false;
				}
			}
			
			bSuccess = executeAliasScript();
			if(false == bSuccess){
				System.out.println("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt run alias creation script.. Returning..");
				slog.info("[ConfigManager / ConfigManager / executeDashboardAliasScript] Couldnt run alias creation script.. Returning..");
				return false;
			}
		} 
		
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / checkPermissionForLogFile]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / executeDashboardAliasScript] Exception occurred.."+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / executeDashboardAliasScript] Stack trace",exc);
			return false;
		}
		
		return true;
	}
	
	/**
	 * Prepare the 'region_config_file.txt' to run alais creation script
	 * @return true if successful
	 */
	private static boolean prepareRegionConfigFile(){
		
		String fileName = "region_config_file.txt";
		File fpRegionFile = null;
		FileWriter fwRegionWriter = null; 
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile] Could not obtain DB connection");
			slog.info("[ConfigManager / ConfigManager / prepareRegionConfigFile] Could not obtain DB connection");
			return false;
		}
		try{
			String filePath = Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir()+keysDirectory;
			fpRegionFile = new java.io.File(filePath, fileName); 
			if (fpRegionFile.isFile() || fpRegionFile.createNewFile()){
				fwRegionWriter = new FileWriter(fpRegionFile, false);
				
				fwRegionWriter.write("# This is the region configuration file for creating dashboard aliases for IX\n"
						+ "# Any line starting with # is treated as a comment line and not processed\n"
						+ "#\n"
						+ "# There should be a single region entry per line\n"
						+ "# Each region entry should consist of two fields that are separated by a <space> character -\n"
						+ "#    1. Region name\n"
						+ "#    2. List of appliances that are part of the region\n"
						+ "# The region name should not include a space\n"
						+ "# The list of appliances can include multiple appliances separated by a <comma> character\n"
						+ "# The list of appliances should not include a space. Not in the appliance FQDN, nor preceding\n"
						+ "# or following the <comma> character\n"
						+ "# Examples -\n"
						+ "#NA fps-pen-wmps62-2.fireeye.com,wmps-71-NA-2.fw-inet1-2-hq-1390.fireeye.com,fps-pen-emps63-1.,fMPS-1.fineitme.info\n"
						+ "#APAC wmps-71-APAC.fw-inet1-2-hq-1390.fireeye.com,wmps-71-APAC-2.fw-inet1-2-hq-1390.fireeye.com\n"
						+ "#EMEA wmps-71-EMEA.fw-inet1-2-hq-1390.fireeye.com,wmps-71-EMEA-2.fw-inet1-2-hq-1390.fireeye.com\n"
						+ "#LTAM wmps-71.FireEye.com\n"
						+ "\n"
						+ "\n");
				
				String selectQuery = "select fqdn, region from appliance where region != ''";
				ResultSet regionSet = runSelectSQLScript(dbConn, selectQuery);
				if(null == regionSet || !regionSet.next()){
					System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile] No Existing properties to be fetched from the database");
					slog.info("[ConfigManager / ConfigManager / prepareRegionConfigFile] No Existing properties to be fetched from the database");
					return true;
				}
				
				regionSet.beforeFirst();
				
				Map<String, HashSet<String>> regionAppliancesMap = new HashMap<String, HashSet<String>>();
				while(regionSet.next()){
					String applianceFQDN = regionSet.getString("fqdn");
					if(null != regionSet.getString("region") && false == regionSet.getString("region").isEmpty()){
						//List<String> regions = Arrays.asList(regionSet.getString("region").split(","));
						//for(int arrIndex=0;arrIndex<regions.size();arrIndex++){
							if(regionAppliancesMap.containsKey(regionSet.getString("region"))){
								regionAppliancesMap.get(regionSet.getString("region")).add(applianceFQDN);						
							}
							else{
								HashSet<String> applianceSet = new HashSet<String>();
								applianceSet.add(applianceFQDN);
								regionAppliancesMap.put(regionSet.getString("region"), applianceSet);
							}
						//}
					}
				}
				
				if(regionAppliancesMap.size()>=1){
					Iterator<Map.Entry<String, HashSet<String>>> it = regionAppliancesMap.entrySet().iterator();
					while (true == it.hasNext())
					{
						Map.Entry<String, HashSet<String>> keyValuePair = (Map.Entry<String, HashSet<String>>) it.next();
						HashSet<String> applianceHashSet = keyValuePair.getValue();
						
						if(applianceHashSet.size() >= 1){
							fwRegionWriter.write(keyValuePair.getKey());
							fwRegionWriter.write(" ");
							
							Iterator<String> setItr = applianceHashSet.iterator();
							while(setItr.hasNext()){
								fwRegionWriter.write(setItr.next());
								if(setItr.hasNext()){
									fwRegionWriter.write(",");
								}
						    }
							
							fwRegionWriter.write("\n");
						}
					}
				}
			}
            
		}
		catch (FileNotFoundException e) {
			System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile]Exception occurred..Exception-"+e);
			e.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile] Exception:"+e);
	    	slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile]Stack Trace-",e);
    	}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile] Exception occured. Exception message - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile] Stack trace-",exc);
			return false;
		}
		finally{
			try
			{
				if (null != fwRegionWriter)
				{
					fwRegionWriter.flush();
					fwRegionWriter.close();
					
					boolean bSuccess = moveFilesToTmpDirectory(fpRegionFile, fileName);
					if(false == bSuccess){
						System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile] Couldnt copy alias creation script support files.. Returning..");
						slog.info("[ConfigManager / ConfigManager / prepareRegionConfigFile] Couldnt copy alias creation script support files.. Returning..");
						return false;
					}
				}
				
				closeConnection(dbConn);
			}
			catch (Exception exc)
			{
				System.out.println("[ConfigManager / ConfigManager / prepareRegionConfigFile]Exception occurred..Exception-"+exc);
				exc.printStackTrace();
				slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile] Exception occured. Exception message - " + exc.getMessage());
				slog.error("[ConfigManager / ConfigManager / prepareRegionConfigFile] Stack trace-",exc);
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Prepare the 'domain_config_file.txt' to run alias creation script
	 * @return true if successful
	 */
	private static boolean prepareDomainConfigFile(){
		String fileName = "domain_config_file.txt";
		File fpDomainFile = null;
		FileWriter fwDomainWriter = null; 
		
		Connection dbConn = getConnection();
		if(null == dbConn){
			System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile] Could not obtain DB connection");
			slog.info("[ConfigManager / ConfigManager / prepareDomainConfigFile] Could not obtain DB connection");
			return false;
		}
		try{
			String filePath = Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir()+keysDirectory;
			fpDomainFile = new java.io.File(filePath, fileName); 
			if (fpDomainFile.isFile() || fpDomainFile.createNewFile()){
				fwDomainWriter = new FileWriter(fpDomainFile, false);
				
				fwDomainWriter.write("# This is the domin configuration file for creating dashboard aliases for IX\n"
						+ "# The domain here is used to filter data shown in IX dashboard based on the domain\n"
						+ "# of the recipient's email address\n"
						+ "# E.g. this scrupt can be used to create a view that shows all attacks targeting\n"
						+ "# users in the China (cn.company.com) domain\n"
						+ "# Any line starting with # is treated as a comment line and not processed\n"
						+ "#\n"
						+ "# There should be a single domain entry per line\n"
						+ "# Each domain entry should consist of two fields that are separated by a <space> character -\n"
						+ "#    1. Domain name\n"
						+ "#    2. List of domains that are part of the domain\n"
						+ "# The domain name should not include a space\n"
						+ "# The list of domains can include multiple domains separated by a <comma> character\n"
						+ "# The list of domains should not include a space\n"
						+ "# Examples -\n"
						+ "#US_DOMAIN us.company.com,ca.company.com\n"
						+ "#APAC_DOMAIN cn.company.com,jp.company.com\n"
						+ "#\n"
						+ "\n"
						+ "\n");
				
				String selectQuery = "select name, value from region_views where type like 'Domain'";
				ResultSet domainSet = runSelectSQLScript(dbConn, selectQuery);
				if(null == domainSet || !domainSet.next()){
					System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile] No Existing properties to be fetched from the database");
					slog.info("[ConfigManager / ConfigManager / prepareDomainConfigFile] No Existing properties to be fetched from the database");
					return true;
				}
				
				domainSet.beforeFirst();
				while(domainSet.next()){
					if(null != domainSet.getString("value") && false == domainSet.getString("value").isEmpty()){
						fwDomainWriter.write(domainSet.getString("name"));
						fwDomainWriter.write(" ");
						fwDomainWriter.write(domainSet.getString("value"));
					}
					fwDomainWriter.write("\n");
				}
			}
			
		}
		catch (FileNotFoundException e) {
			System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile]Exception occurred..Exception-"+e);
			e.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile] Exception:"+e);
	    	slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile]Stack Trace-",e);
    	}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile] Exception occured. Exception message - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile] Stack trace-",exc);
			return false;
		}
		finally{
			try
			{
				if (null != fwDomainWriter)
				{
					fwDomainWriter.flush();
					fwDomainWriter.close();
					
					boolean bSuccess = moveFilesToTmpDirectory(fpDomainFile, fileName);
					if(false == bSuccess){
						System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile] Couldnt copy alias creation script support files.. Returning..");
						slog.info("[ConfigManager / ConfigManager / prepareDomainConfigFile] Couldnt copy alias creation script support files.. Returning..");
						return false;
					}
				}
				closeConnection(dbConn);
			}
			catch (Exception exc)
			{
				System.out.println("[ConfigManager / ConfigManager / prepareDomainConfigFile]Exception occurred..Exception-"+exc);
				exc.printStackTrace();
				slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile] Exception occured. Exception message - " + exc.getMessage());
				slog.error("[ConfigManager / ConfigManager / prepareDomainConfigFile] Stack trace-",exc);
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Move alias config files from /usr/share/tomcat/ix_keys directory to /tmp directory
	 * @param sourceLocation
	 * @param fileName
	 * @return true if successful
	 */
	private static boolean moveFilesToTmpDirectory(File sourceLocation, String fileName){
		try{
			File dest = new File("/tmp/"+fileName);
			
			FileUtils.copyFile(sourceLocation, dest);
		}
		catch(IOException io){
			System.out.println("[ConfigManager / ConfigManager / moveFilesToTmpDirectory]Exception occurred..Exception-"+io);
			io.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / moveFilesToTmpDirectory] IO Exception occurred.."+io.getMessage());
			slog.error("[ConfigManager / ConfigManager / moveFilesToTmpDirectory] Stack trace",io);
			return false;
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / moveFilesToTmpDirectory]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / moveFilesToTmpDirectory] Exception occurred.."+exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / moveFilesToTmpDirectory] Stack trace",exc);
			return false;
		}
		return true;
	}
	
	/**
	 * Run the command to execute the alias script
	 * @return true if successful
	 */
	private static boolean executeAliasScript(){
		String output;
		try{
			String aliasRunCommand = "/tmp/create_dashboard_aliases.py -d /tmp/domain_config_file.txt -r /tmp/region_config_file.txt -a /tmp/adapter_config_file.txt -s";
			Process runAliasScript = Runtime.getRuntime().exec(aliasRunCommand);
			BufferedReader br = new BufferedReader(new InputStreamReader(runAliasScript.getInputStream()));
			while ((output = br.readLine()) != null){
				slog.info(output);
			}   
			
			runAliasScript.waitFor();
			runAliasScript.destroy();
			
			System.out.println("[ConfigManager / ConfigManager / executeAliasScript] Dashboard aliases successfully created");
			slog.info("[ConfigManager / ConfigManager / executeAliasScript] Dashboard aliases successfully created");
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / executeAliasScript]Exception occurred..Exception-"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / executeAliasScript] Exception occured. Exception message - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / executeAliasScript] Stack trace-",exc);
			return false;
		}
		return true;
	}
	
	/**
	 * Start tomcat service
	 * @return true if successfully started
	 */
	private static boolean startTomcatService(){
		String output;
		try{
			System.console().writer().println("[ConfigManager / ConfigManager / stopTomcatService]Attempting to start tomcat service.. Please wait..");
			slog.info("[ConfigManager / ConfigManager / stopTomcatService]Attempting to start tomcat service");
			Process startService = Runtime.getRuntime().exec("sudo service tomcat start");
			BufferedReader br = new BufferedReader(new InputStreamReader(startService.getInputStream()));
			while ((output = br.readLine()) != null){
				System.console().writer().println(output);
			}   
			startService.waitFor();
			startService.destroy();
			return true;

		}
		catch(Exception exc){
			System.console().writer().println("[ConfigManager / ConfigManager / startTomcatService]Exception occurred:"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / startTomcatService] Exception occurred:"+exc);
        	slog.error("[ConfigManager / ConfigManager / startTomcatService] Stack Trace-",exc);
			return false;
		}
	}
	
	/**
	 * Stop tomcat service
	 * @return true if successfully stopped
	 */
	private static boolean stopTomcatService(){
		String output;
		try{
			System.console().writer().println("[ConfigManager / ConfigManager / stopTomcatService]Attempting to stop tomcat service.. Please wait..");
			slog.info("[ConfigManager / ConfigManager / stopTomcatService]Attempting to stop tomcat service");
			Process stopService = Runtime.getRuntime().exec("sudo service tomcat stop");
			BufferedReader br = new BufferedReader(new InputStreamReader(stopService.getInputStream()));
			while ((output = br.readLine()) != null){
				System.console().writer().println(output);
			}   
		 	stopService.waitFor();
            stopService.destroy();
			return true;
		}
		catch(Exception exc){
			System.console().writer().println("[ConfigManager / ConfigManager / stopTomcatService]Exception occurred:"+exc);
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / stopTomcatService] Exception occurred:"+exc);
        	slog.error("[ConfigManager / ConfigManager / stopTomcatService] Stack Trace-",exc);
			return false;
		}
	}
	
	/**
	 * Main function
	 * @param args
	 */
	public static void main(String args[]){
		
		System.out.println("#	Copyright (c) FireEye Inc, 2017. All rights reserved.\n"
				+ "#	\n"
				+ "#	This utility is intended to be run by the customer/FireEye as part of IX deployment and configuration\n"
				+ "#	This utility is necessary when the operator has to read and/or set adapter configuration properties\n"
				+ "#	from SSH command line (in the event that IX GUI is not accessible)\n"
				+ "#	This utility is intended to run on the IX VM\n"
				+ "#	\n"
				+ "#	This utility has to be run under the context of the 'tomcat' user (via the 'ixoperator user) \n"
				+ "#	- The logged in 'ixoperator' user runs this utility using the following command -\n"
				+ "#	sudo -u tomcat java -jar Config_Manager.jar [Command Parameters (see below)]\n"
				+ "#	\n"
				+ "#	\n"
				+ "#	This utility performs the following (Note the usage of the command)-\n"
				+ "#	1. Read all the adapters whose properties are configured\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -getAdapters\n"
				+ "#	2. Read all the properties for a given adapter in both concise and detailed format\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -outputFormat <concise|detailed> -getProperty -adapterName <adapterName>\n"
				+ "#	3. Read all the property details for a given adapter and given propertyName in both concise and detailed format\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -outputFormat <concise|detailed> -getProperty -adapterName <adapterName> -propertyName <propertyName>\n"
				+ "#	4. Set the property value given the property name and property value\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -setProperty -propertyName <propertyName> -propertyValue <propertyValue>\n"
				+ "#	5. Get the appliance details given the appliance hostname/FQDN value\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -getAppliance <applianceName>\n"
				+ "#	6. Get the region/view details given the region/view name\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -getRegionView <regionViewName>\n"
				+ "#	7. Delete the appliance record given the appliance hostname/FQDN value\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -deleteAppliance <applianceName>\n"
				+ "#	8. Delete the region/view record given the region/view name\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -deleteRegionView <regionViewName>\n"
				+ "#	9. Add/Modify the appliance record given the appliance name\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -setAppliance -applianceName <applianceName> -applianceType <applianceType> -region <region> "
				+ "-country <country> -ipAddress <IP_address> -username <Username> -password <password> -version <Version>\n"
				+ "#	10. Add/Modify the region/view record given the region/view name and view type\n"
				+ "#		sudo -u tomcat java -jar Config_manager.jar -setRegionView -regionViewName <regionViewName> -viewType <Appliance|Domain> -readableName <readableName> -domainValue <domainValue>\n"
				+ "#	\n"
				+ "#	outputFormat - concise-prints name,value,adapterName and display_name of the property\n"
				+ "#	outputFormat - detailed-prints all the details of the property\n"
				+ "#	viewType - Appliance-creates a region view type where the appliance belongs to\n"
				+ "#	viewType - Domain-creates a view type considering the domains where alert occurred\n"	
 				+ "#	The flags - outputFormat and propertyName are optional and the flag - adapterName is mandatory for 'getProperty'\n"
 				+ "#	The flags - propertyName and propertyValue are mandatory for 'setProperty'\n"
 				+ "#	The flags - applianceName is mandatory for 'setAppliance'\n"
 				+ "#	The flags - regionViewName and viewType are mandatory for 'setRegionView'\n"
 				+ "#	\n");
		
		
		
		boolean bSuccess = false;
		bSuccess = checkPermissionForLogFile();
		if(false == bSuccess){
			System.out.println("[ConfigManager / ConfigManager / main]Cannot create log file.. Access denied.. The utility has to be run under the context of the 'tomcat' user..Cannot continue...Returning failure..");
			slog.info("[ConfigManager / ConfigManager / main]Cannot create log file.. Access denied.. Cannot continue...Returning failure..");
			return;
		}
		
		String outputFormat = "concise";
		String adapterName = null;
		String propertyName = "all";
		String propertyValue = null;
		
		String applianceGetName = null;
		String regionViewGetName = null;
		
		String applianceSetName= null;
		String applianceType = null;
		String applianceRegion = null;
		String applianceCountry = null;
		String applianceIPAddress = null;
		String applianceUsername = null;
		String appliancePassword = null;
		String applianceVersion = null;
		
		String regionViewSetName = null;
		String viewType = null;
		String readableName = null;
		String domainValue = null;
		
		boolean getProperty = false;
		boolean setProperty = false;
		boolean getAdapters = false;
		boolean getAppliance = false;
		boolean setAppliance = false;
		boolean deleteAppliance = false;
		boolean getRegionView = false;
		boolean setRegionView = false;
		boolean deleteRegionView = false;
		
		boolean addModifySuccessful = false;
		
		CommandLine command = null;
		try{
			command = getCommand(args);
			
			if(command == null)
				return;
			
			int countFlags = 0;
			
			if(command.hasOption("setProperty")){
				setProperty = true;
				countFlags++;
			}
			
			if(command.hasOption("getProperty")){
				getProperty = true;
				countFlags++;
			}
			
			if(command.hasOption("getAdapters")){
				getAdapters = true;
				countFlags++;
			}
			
			if(command.hasOption("getAppliance")){
				getAppliance = true;
				countFlags++;
			}
			
			if(command.hasOption("setAppliance")){
				setAppliance = true;
				countFlags++;
			}
			
			if(command.hasOption("deleteAppliance")){
				deleteAppliance = true;
				countFlags++;
			}
			
			if(command.hasOption("getRegionView")){
				getRegionView = true;
				countFlags++;
			}
			
			if(command.hasOption("setRegionView")){
				setRegionView = true;
				countFlags++;
			}
			
			if(command.hasOption("deleteRegionView")){
				deleteRegionView = true;
				countFlags++;
			}
			
			if(countFlags > 1){
				System.out.println("[ConfigManager / ConfigManager / main]Error in command.. You can use just one of these options - "
						+ "'setProperty','getProperty','getAdapters', 'getAppliance','setAppliance','deleteAppliance','getRegionView','setRegionView','deleteRegionView'.. "
						+ "Cannot continue.. Returing failure");
				slog.info("[ConfigManager / ConfigManager / main]Error in command.. You can use just one of these options - "
						+ "'setProperty','getProperty','getAdapters','getAppliance','setAppliance','deleteAppliance','getRegionView','setRegionView','deleteRegionView'.. "
						+ "Cannot continue.. Returing failure");
				return;
			}
			else if(countFlags == 0){
				System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify one of these options - "
						+ "'setProperty','getProperty','getAdapters','getAppliance','setAppliance','deleteAppliance','getRegionView','setRegionView','deleteRegionView'.. "
						+ "Cannot continue.. Returing failure");
				slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify one of these options - "
						+ "'setProperty','getProperty','getAdapters','getAppliance','setAppliance','deleteAppliance','getRegionView','setRegionView','deleteRegionView'.. "
						+ "Cannot continue.. Returing failure");
				return;
			}
			
			if(command.getOptionValue("outputFormat") != null){
				outputFormat = command.getOptionValue("outputFormat");
				if(null != outputFormat && false == outputFormat.isEmpty()){
					if(!outputFormat.equalsIgnoreCase("concise") && !outputFormat.equalsIgnoreCase("detailed")){
						System.out.println(" [ConfigManager / ConfigManager / main] Error in command.. Please specify the correct output format - 'concise' or 'detailed'.. "
								+ "Cannot continue.. Returing failure");
						slog.info(" [ConfigManager / ConfigManager / main] Error in command.. Please specify the correct output format - 'concise' or 'detailed'.. "
								+ "Cannot continue.. Returing failure");
						return;
					}
				}
			}
		
			if(command.getOptionValue("adapterName") != null){
				adapterName = command.getOptionValue("adapterName");
				if (null == adapterName || true == adapterName.trim().isEmpty()) {
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please use -adapterName parameter to specify a non-empty adapter name. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please use -adapterName parameter to specify a non-empty adapter name. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("propertyName") != null){
				propertyName = command.getOptionValue("propertyName");
				if(null == propertyName || true == propertyName.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("propertyValue") != null){
				propertyValue = command.getOptionValue("propertyValue");
				if(null == propertyValue || true == propertyValue.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyValue parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyValue parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			//setAppliance arguments start
			if(command.getOptionValue("applianceName") != null){
				applianceSetName = command.getOptionValue("applianceName");
				if(null == applianceSetName || true == applianceSetName.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("applianceType") != null){
				applianceType = command.getOptionValue("applianceType");
				if(null == applianceType || true == applianceType.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceType parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceType parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("region") != null){
				applianceRegion = command.getOptionValue("region");
				if(null == applianceRegion || true == applianceRegion.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -region parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -region parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("country") != null){
				applianceCountry = command.getOptionValue("country");
				if(null == applianceCountry || true == applianceCountry.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -country parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -country parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("ipAddress") != null){
				applianceIPAddress = command.getOptionValue("ipAddress");
				if(null == applianceIPAddress || true == applianceIPAddress.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -ipAddress parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -ipAddress parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("username") != null){
				applianceUsername = command.getOptionValue("username");
				if(null == applianceUsername || true == applianceUsername.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -username parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -username parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("password") != null){
				appliancePassword = command.getOptionValue("password");
				if(null == appliancePassword || true == appliancePassword.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -password parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -password parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("version") != null){
				applianceVersion = command.getOptionValue("version");
				if(null == applianceVersion || true == applianceVersion.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -version parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -version parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			//setAppliance arguments end
			
			//setRegionView arguments start
			if(command.getOptionValue("regionViewName") != null){
				regionViewSetName = command.getOptionValue("regionViewName");
				if(null == regionViewSetName || true == regionViewSetName.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -regionViewName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -regionViewName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("viewType") != null){
				viewType = command.getOptionValue("viewType");
				if(null == viewType || true == viewType.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -viewType parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -viewType parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
				else if((!viewType.equalsIgnoreCase("Domain") && !viewType.equalsIgnoreCase("Appliance"))){
					System.out.println(" [ConfigManager / ConfigManager / main] Error in command.. Please specify the correct viewType - 'Domain' or 'Appliance'.. "
							+ "Cannot continue.. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main] Error in command.. Please specify the correct viewType - 'Domain' or 'Appliance'.. "
							+ "Cannot continue.. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("readableName") != null){
				readableName = command.getOptionValue("readableName");
				if(null == readableName || true == readableName.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -readableName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -readableName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			
			if(command.getOptionValue("domainValue") != null){
				domainValue = command.getOptionValue("domainValue");
				if(null == domainValue || true == domainValue.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -domainValue parameter..'Appliance' or 'Domain' "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -domainValue parameter.. 'Appliance' or 'Domain"
							+ "Cannot continue further. Returing failure");
					return;
				}
			}
			//setRegionView arguments end
			
			bSuccess = false;
			if(true == getAdapters){
				//fetch all adapters
				bSuccess = getAllAdapters();
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to fetch all adapters.. ");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to fetch all adapters.. ");
					return;
				}
			}
			
			if(true == setProperty){
				//set property
				if(null == propertyName || true == propertyName.isEmpty() || null == propertyValue || true == propertyValue.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyValue and -propertyName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -propertyValue and -propertyName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
				bSuccess = stopTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			return;
	    		}
				bSuccess = validateAndSetPropertyValue(propertyName, propertyValue);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to set property value for property - "+propertyName);
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to set property value for property - "+propertyName);
					return;
				}
				
				System.out.println("[ConfigManager / ConfigManager / main] Property "+propertyName+" modified successfully");
				slog.info("[ConfigManager / ConfigManager / main] Property "+propertyName+" modified successfully");
				
				bSuccess = startTomcatService();
        		if(false == bSuccess){
        			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
        			slog.info("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
        			return;
        		}
			}
			
			if(true == getProperty){
				//getProperty
				bSuccess = getProperties(outputFormat, adapterName, propertyName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to get properties for specified values");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to get properties for specified values");
					return;
				}
			}
			
			if(true == getAppliance){
				//getAppliance
				if(command.getOptionValue("getAppliance") != null){
					applianceGetName = command.getOptionValue("getAppliance");
				}
				else if(null == command.getOptionValue("getAppliance") || true == command.getOptionValue("getAppliance").isEmpty()){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to get appliance details.. Please specify the appliance host name/FQDN");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to get appliance details.. Please specify the appliance host name/FQDN");
					return;
				}
				bSuccess = getApplianceDetails(applianceGetName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error occurred.. Unable to get appliance details..");
					slog.info("[ConfigManager / ConfigManager / main]Error occurred.. Unable to get appliance details..");
					return;
				}
			}
			
			if(true == setAppliance){
				//add or modify appliance record
				if(null == applianceSetName || true == applianceSetName.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceName parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -applianceName parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
				
				bSuccess = stopTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			return;
	    		}
				
				System.out.println("[ConfigManager / ConfigManager / main] Appliance "+applianceSetName+" modified/added successfully");
				slog.info("[ConfigManager / ConfigManager / main] Appliance "+applianceSetName+" modified/added successfully");
				
				bSuccess = validateAndSetAppliance(applianceSetName, applianceType, applianceRegion, applianceCountry, applianceIPAddress, applianceUsername, appliancePassword, applianceVersion);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to set the Appliance record");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to set the Appliance record");
					return;
				}
				
				bSuccess = startTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			return;
	    		}
				
				addModifySuccessful = true;
			}
			
			if(true == deleteAppliance){
				//deleteAppliance
				if(command.getOptionValue("deleteAppliance") != null){
					applianceGetName = command.getOptionValue("deleteAppliance");
				}
				else if(null == command.getOptionValue("deleteAppliance") || true == command.getOptionValue("deleteAppliance").isEmpty()){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to delete appliance record.. Please specify the appliance host name/FQDN");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to delete appliance record.. Please specify the appliance host name/FQDN");
					return;
				}
				
				bSuccess = stopTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			return;
	    		}
				
				bSuccess = deleteAppliance(applianceGetName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error occurred.. Unable to delete appliance record..");
					slog.info("[ConfigManager / ConfigManager / main]Error occurred.. Unable to delete appliance record..");
					return;
				}
				
				System.out.println("[ConfigManager / ConfigManager / main] Appliance "+applianceSetName+" deleted successfully");
				slog.info("[ConfigManager / ConfigManager / main] Appliance "+applianceSetName+" deleted successfully");
				
				bSuccess = startTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			return;
	    		}
				
				addModifySuccessful = true;
			}
			
			if(true == getRegionView){
				//getRegionView
				if(command.getOptionValue("getRegionView") != null){
					regionViewGetName = command.getOptionValue("getRegionView");
				}
				else if(null == command.getOptionValue("getRegionView") || true == command.getOptionValue("getRegionView").isEmpty()){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to get region/view details.. Please specify the region/view name");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to get region/view details.. Please specify the region/view name");
					return;
				}
				bSuccess = getRegionViewDetails(regionViewGetName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error occurred.. Unable to get region/view details..");
					slog.info("[ConfigManager / ConfigManager / main]Error occurred.. Unable to get region/view details..");
					return;
				}
			}
			
			if(true == setRegionView){
				//add or modify region/view record
				if(null == regionViewSetName || true == regionViewSetName.isEmpty() || null == viewType || true == viewType.isEmpty()){
					System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -regionViewName and -viewType parameter.. "
							+ "Cannot continue further. Returing failure");
					slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty value for -regionName and -viewType parameter.. "
							+ "Cannot continue further. Returing failure");
					return;
				}
				if(viewType.equalsIgnoreCase("Domain")){
					if(null == domainValue || true == domainValue.isEmpty()){
						System.out.println(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty domain values for -domainValue parameter.. "
								+ "Cannot continue further. Returing failure");
						slog.info(" [ConfigManager / ConfigManager / main]Error in command.. Please specify a non-empty domain values for -domainValue parameter.. "
								+ "Cannot continue further. Returing failure");
						return;
					}
				}
				else if(viewType.equalsIgnoreCase("Appliance")){
					domainValue = null;
				}
				
				bSuccess = stopTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			return;
	    		}
				
				bSuccess = validateAndSetRegionView(regionViewSetName, readableName, viewType, domainValue);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to set the regionView record");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to set the regionView record");
					return;
				}
				
				System.out.println("[ConfigManager / ConfigManager / main] Region/View  "+regionViewSetName+" added/modified successfully");
				slog.info("[ConfigManager / ConfigManager / main] Region/View "+regionViewSetName+" added/modified successfully");
				
				bSuccess = startTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			return;
	    		}
				
				addModifySuccessful = true;
			}
			
			if(true == deleteRegionView){
				//deleteRegionView
				if(command.getOptionValue("deleteRegionView") != null){
					regionViewGetName = command.getOptionValue("deleteRegionView");
				}
				else if(null == command.getOptionValue("deleteRegionView") || true == command.getOptionValue("deleteRegionView").isEmpty()){
					System.out.println("[ConfigManager / ConfigManager / main]Error.. Unable to delete region/view record.. Please specify the region/viewname");
					slog.info("[ConfigManager / ConfigManager / main]Error.. Unable to delete region/view record.. Please specify the region/view");
					return;
				}
				bSuccess = stopTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to stop tomcat service..");
	    			return;
	    		}
				
				bSuccess = deleteRegionView(regionViewGetName);
				if(false == bSuccess){
					System.out.println("[ConfigManager / ConfigManager / main]Error occurred.. Unable to delete region/view record..");
					slog.info("[ConfigManager / ConfigManager / main]Error occurred.. Unable to delete region/view record..");
					return;
				}
				
				System.out.println("[ConfigManager / ConfigManager / main] Region/View  "+regionViewGetName+" deleted successfully");
				slog.info("[ConfigManager / ConfigManager / main] Region/View "+regionViewGetName+" deleted successfully");
				
				bSuccess = startTomcatService();
				if(false == bSuccess){
	    			System.console().writer().println("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			slog.info("[ConfigManager / ConfigManager / main] Unable to start tomcat service..");
	    			return;
	    		}
				
				addModifySuccessful = true;
			}
			
			if(true == deleteAppliance || true == deleteRegionView || true == setAppliance || true == setRegionView){
				if(true == addModifySuccessful){
					//invoke alias creation script
					bSuccess = executeDashboardAliasScript();
					if(false == bSuccess){
						System.out.println("[ConfigManager / ConfigManager / main]Error occurred while executing dashboard alias creation script..");
						slog.info("[ConfigManager / ConfigManager / main] Error occurred while executing dashboard alias creation script..");
						return;
					}
				}
			}
			
		}
		catch(Exception exc){
			System.out.println("[ConfigManager / ConfigManager / main]Error occurred obtaining parsing command line arguments. Error message is - " + exc.getMessage());
			exc.printStackTrace();
			slog.error("[ConfigManager / ConfigManager / main]Error occurred obtaining parsing command line arguments. Error message is - " + exc.getMessage());
			slog.error("[ConfigManager / ConfigManager / main]Stack trace - ",exc);
			return;
		}
	}
	
}
