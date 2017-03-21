package com.src.utils;

import java.io.File;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

public class Utils {
		
	//private static Map<String, String> hm = new ConcurrentHashMap<String, String>();
	//private static Map<String, String> auditHM = new ConcurrentHashMap<String, String>();
	//private static Map<String, String> whitelistHM = new ConcurrentHashMap<String, String>();
	
	//private static Calendar calendar = Calendar.getInstance();
	//private static Date now;
	//private static String propertyFileName = "is.properties";
	//private static String propertyFile = (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+propertyFileName;
	private static String keyStoreFileName = "ix_keystore.jceks";
	private static String keysDirectory = "ix_keys/";
	private static String keyStoreFilePath= (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+keysDirectory+keyStoreFileName;
	//private static String keyStoreFileNameData = "ix_keystore_data.jceks";
	//private static String keyStoreFilePathData= (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+keyStoreFileNameData;
	private static String keyStoreFilePasswordFileName = "ix_keystore_password.txt";
	private static String keyStorePasswordFilePath = (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+keysDirectory+keyStoreFilePasswordFileName;
	private static String mySqlConfigFileName = "mysql_config.txt";
	private static String mySqlConfigFile = (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+keysDirectory+mySqlConfigFileName;
	private static String authorizationPropertyFileName = "ix_authorization_config.properties";
	private static String authorizationPropertyFile = (Utils.fetchTomcatHome()!= null?Utils.fetchTomcatHome():Utils.fetchHomeDir())+authorizationPropertyFileName;
	
	//private static String propertyFile = propertyFileName;
	//private static SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	//private static SimpleDateFormat FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	//private static String line = "";
	//private static String cvsSplitBy = ",";
	//static Logger slog = Logger.getLogger("ServerLog");
	//static Logger alog = Logger.getLogger("OTHER_LOGGER");
	//private static String MD5 = "MD5";
	//private static String MURL = "MURL";
	//private static String MD5_REGEX = "^[a-f0-9]{32}$";
	//private static String URL_REGEX = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";	
	//private static Pattern urlpattern = Pattern.compile(URL_REGEX, Pattern.CASE_INSENSITIVE);
	//private static Pattern md5pattern = Pattern.compile(MD5_REGEX, Pattern.CASE_INSENSITIVE);	
	//public static String  wlHashVal;
	//private static Boolean incrementalUpdatesOnly;
	//private static boolean addedBlockedEntry = true;
	//private static int SB_SIZE = 128;
	//private static String HTTP_PREFIX = "http";
	//private static String HTTPS_PREFIX = "https";
	//public static String HTTP_STR = "http://";
	//private static String GET = "GET";
	//private static String POST = "POST";
	//private static String HOST = "Host";
	//public static int STRBUFFER_SIZE = 2048;
	//public static String DETAILS_DELIM = "::";
	
	//public static Map<String, String> malwareNameHM = new HashMap<String, String>();
	/*public static List<String> malwareTypeRankinAL = new ArrayList<String>()
	{
		{
			add("vm-bot-command");
			add("av-match");
			add("archive");
		}
	};
	
	public static String getWlHashVal() {
		return wlHashVal;
	}

	public static void setWlHashVal(String wlHashVal) {
		Utils.wlHashVal = wlHashVal;
	}

	public static String getLine() {
		return line;
	}

	public static void setLine(String line) {
		Utils.line = line;
	}

	public static String getCvsSplitBy() {
		return cvsSplitBy;
	}

	public static void setCvsSplitBy(String cvsSplitBy) {
		Utils.cvsSplitBy = cvsSplitBy;
	}

	public static long currentTS() {
		// a java current time (now) instance
		now = calendar.getTime();
		java.sql.Timestamp ts = new java.sql.Timestamp(now.getTime());
		return ts.getTime();
	}
	
	public static String currentTime() {
		// a java current time (now) instance
		now = calendar.getTime();
		return (now.toString());
	}

	public static String currentTimeFromSystem() {
		// a java current time (now) instance
		Date d = new Date(System.currentTimeMillis());
		return (d.toString());
	}
	
	public static Timestamp String2Timestamp(String ts_string) {
		java.sql.Timestamp timestamp = null;
		if (ts_string != null && !ts_string.equals("")) {
			timestamp = Timestamp.valueOf((ts_string.contains("Z")?Utils.dateFormatConverter(ts_string):ts_string));
			java.util.Date date = timestamp;
			slog.info("Timestamp/Date: "+ date.toString());
		}
		return timestamp;
	}
	
	public static String dateFormatConverter(String oldDate) {
		
		Date date = null;
		String newFormat = null;
		
		try {
			date = formatter.parse(oldDate.substring(0, 20));
		} catch (ParseException e) {
			slog.debug("dateFormatConverter parse exception: "+e.getMessage());
		}
		if (date != null) {
			slog.debug("OldDate-->"+oldDate);
			newFormat = FORMATTER.format(date);
			slog.debug("NewDate-->"+newFormat);
		}
		return newFormat;
	}*/
	
	
	public static String fetchHomeDir () {
		String homeDir = (System.getProperty("user.home") + File.separator);
		return homeDir;
	}
	
	public static String fetchTomcatHome () {
		String ev = null;
		try {
			ev = System.getenv("CATALINA_HOME");
			if ( ev != null ) {
				return (ev + File.separator);
			}
			Map<String, String> envMap = System.getenv();
			SortedMap<String, String> sortedEnvMap = new TreeMap<String, String>(envMap);
			Set<String> keySet = sortedEnvMap.keySet();
			for (String key : keySet) {
				String value = envMap.get(key);
			}

		}catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return ev;
	}
	/*
	public static boolean validMD5(String input) {
		if (input == null || input.equals(""))
			return false;
		Matcher matcher = md5pattern.matcher(input);
	    return (matcher.matches());
	}
	
	
	public static String fetchHighestRankedMalware(Map<String, String> hm) {
		for (String elem : malwareTypeRankinAL) {
			if (hm.containsKey(elem)) {
				return ((String)hm.get(elem));
			}
		}
		return null;
	}
	
	public static void printHashMap(Map<String, String> map) {
		for (Map.Entry<String,String> entry : map.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			slog.info("key: "+ key + ", val: "+value);
		}
	}
	
	public static String parseHTTPHeader(String header) {
		
		String host = "";
		String path = "";
		String stdelim = "|";
		
		String PATTERN_TO_MATCH = "(\\r|\\n)";
		boolean fqdn = false;
		StringBuffer sb = new StringBuffer(SB_SIZE);
		String newHeader = "";
			
		newHeader = header.replaceAll(PATTERN_TO_MATCH, stdelim);
		slog.info("http-header: "+newHeader);
		
		if (newHeader != null && !newHeader.equals("")) {
			StringTokenizer st = new StringTokenizer(newHeader, stdelim, false);
			
			while (st.hasMoreTokens()) {
				String tok = st.nextToken().trim();
				if (tok.startsWith(POST))
					break;
				if (tok.startsWith(GET)) {
					String[] fields = tok.trim().split(" ");
					slog.info("GET values: "+ fields.toString());
					if (fields.length >= 1) {
						path = fields[1].trim();
						slog.info("path: "+ path);
					}
					if (path.startsWith(HTTP_PREFIX) || path.startsWith(HTTPS_PREFIX)) {
						fqdn=true;
						break;
					}
				}
				if (tok.startsWith(HOST)) {
					String[] fields = tok.trim().split(":");
					slog.info("Host values: "+ fields.toString());
					if (fields.length >= 1) {
						host = fields[1].trim();
						slog.info("host: "+ host);
					}
				}
				if(!path.equals("") && !host.equals(""))
					break;
			}
			
			if (fqdn) {
				sb.append(path);
			}
			else if (host != null && !host.equals("")) {
				sb.append(HTTP_STR).append(host);
				
				if (path != null && !path.equals(""))
					sb.append(path);
			}
			slog.info("malicious_url extracted from http header: "+ sb.toString()+", length: "+sb.length());
		}
		return (sb.toString());
	}
	
	public static String parseChannelHeader(String header, String port, String address) {
		
		String host = "";
		String path = "";
		
		String stdelim = "|";
		String HTTP_STD_PORT = "80";
		String PATTERN_TO_MATCH = "::~~";
		StringBuffer sb = new StringBuffer(SB_SIZE);
		String newHeader = "";
		boolean fqdn = false;
		
		newHeader = header.replaceAll(PATTERN_TO_MATCH, stdelim);
		slog.info("channel-http-header: "+newHeader);
		
		if (newHeader != null && !newHeader.equals("")) {
			StringTokenizer st = new StringTokenizer(newHeader, stdelim, false);
			
			while (st.hasMoreTokens()) {
				String tok = st.nextToken().trim();
				if (tok.startsWith(POST)) 
					break;
				if (tok.startsWith(GET)) {
					String[] fields = tok.trim().split(" ");
					slog.info("GET values: "+ fields.toString());
					if (fields.length >= 1) {
						path = fields[1].trim();
						slog.info("path: "+ path);
					}
					if (path.startsWith(HTTP_PREFIX) || path.startsWith(HTTPS_PREFIX)) {
						fqdn=true;
						break;
					}
				}
				if (tok.startsWith(HOST)) {
					String[] fields = tok.trim().split(":");
					slog.info("Host values: "+ fields.toString());
					if (fields.length > 1) {
						host = fields[1].trim();
						slog.info("host: "+ host);
					}
				}
				if(!path.equals("") && !host.equals(""))
					break;
			}
			
			if (host == null || host.equals("") && !fqdn) {
				if (path != null && !path.equals("") && !fqdn && address != null && !address.equals("")) {
					host = address;
				}
				else
					return null;
			}
			
			if (fqdn) {
				sb.append(path);
			}
			else {
				sb.append(HTTP_STR); 
				if (host != null && !host.equals("")) {
					if (port!=null && !port.equals("") && !port.equals(HTTP_STD_PORT))
						sb.append(host).append(":").append(port);
					else 
						sb.append(host);
				}
				else if (address!=null && !address.equals("")) {
					slog.info("service->address: "+address);
					sb.append(address);
					if (port!=null && !port.equals("") && !port.equals(HTTP_STD_PORT)) {
						slog.info("service->port: "+port);
						sb.append(":").append(port);
					}
				}
				if (path != null && !path.equals(""))
					sb.append(path);
			}
		}
		slog.info("malicious_url extracted from channel header: "+ sb.toString());
		return sb.toString();
	}


	public static DataAccessObject DAOClone(DataAccessObject o) {
		
		DataAccessObject newDao = new DataAccessObject();
		newDao.setDetails(o.getDetails());
		newDao.setMalicious_url(o.getMalicious_url());
		newDao.setMd5_hash(o.getMd5_hash());
		newDao.setRecipient_email(o.getRecipient_email());
		newDao.setTimestamp(o.getTimestamp());
		newDao.setAppliance(o.getAppliance());
		newDao.setMalwareName(o.getMalwareName());
		newDao.setMalwareId(o.getMalwareId());
		newDao.setVisited(o.getVisited());
		newDao.setMurl_visited(o.getMurl_visited());
		newDao.setClam_visited(o.getClam_visited());
		
		return newDao;
	}
	
	
	public static boolean validURL(String input) {
		if (input == null || input.equals(""))
			return false;
		
		if ( (input.startsWith("http")) || (input.startsWith("https")) || (input.startsWith("ftp")) || (input.startsWith("file"))) {
			////Matcher matcher = urlpattern.matcher(input);
			////slog.debug("malicious URL pattern match: " + matcher.matches() +", for url: "+input);
			slog.info("malicious URL pattern match: " + input);
			////return(matcher.matches());
			return true; 
		}
		else 
			return false;
	}
	
	public static String fileHashVal(FileInputStream fis) {
		MessageDigest md=null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			slog.error(e.getMessage());
		}

        byte[] dataBytes = new byte[1024];
 
        int nread = 0; 
        try {
			while ((nread = fis.read(dataBytes)) != -1) {
			  md.update(dataBytes, 0, nread);
			}
		} catch (IOException e) {
			slog.error(e.getMessage());
		};
        byte[] mdbytes = md.digest();
 
        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }
 
        return sb.toString();
 
	}
	
	public static int write(ClamAVDTO dto) {
		int val = 0;
		if (!dto.getContent().isEmpty()) {
			val = write2File(dto.getFileName(), dto.getContent());
			////Utils.logAuditTrail(MD5);
		}
		else
			val = write2File(dto.getFileName(), "");
		return val;
	}
	
	public static int read(WhitelistDTO dto) {
		int retval = 0;
		retval = readFromFile(dto.getFileName(), true);
		auditWhiteList();
		return retval;
	}
	
	public static int readFromFile(String filename, boolean createMap) {
		int retval = 0;
		String key = null, val = "null";
		BufferedReader br = null;
		
		try {
			String wlFileHashVal = Utils.fileHashVal(new FileInputStream(filename));

			if (Utils.getWlHashVal() != null && wlFileHashVal != null && Utils.getWlHashVal().equals(wlFileHashVal)) {
				slog.info("new whitelist hash unchanged since last read: "+ wlFileHashVal + ", whitelistHM.size is : "+ Utils.whitelistHM.size());
				return Utils.whitelistHM.size();
			}
			Utils.setWlHashVal(wlFileHashVal);
			
			br = new BufferedReader(new FileReader(filename));
			if (br != null && createMap)
				Utils.whitelistHM.clear();

			
			while ((line = br.readLine()) != null) {	
				// use comma as separator
				String[] wlValues = line.split(cvsSplitBy);
				key =  wlValues[0];
				if (key != null) {
					if (createMap) {
						if (!Utils.whitelistHM.containsKey(key))
							Utils.whitelistHM.put(key, val);
					}
				}
			}
			slog.info("whitelist values: " + whitelistHM.keySet().toString());
			retval = Utils.whitelistHM.size();
			
		} catch (FileNotFoundException e) {
			slog.error("FileNotFoundException: "+e.getMessage());
		} catch (IOException e) {
			slog.error("IOException: "+e.getMessage());
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					slog.error("IOException: "+e.getMessage());
				}
			}
		}
		return retval;
	}
	
	
	public static void auditWhiteList() {
		try {
		
			Iterator<Map.Entry<String, String>> entries =  Utils.auditHM.entrySet().iterator();
			while (entries.hasNext()) {
				Map.Entry<String, String> entry = entries.next();
				String key = entry.getKey();
				if (key!= null && !Utils.whitelistHM.containsKey(key)) {
					String tsVal = (String)auditHM.get(key);
					alog.info("REMOVING blocked entry: " + key + ", created at: " + tsVal);
					auditHM.remove(key);
				}
			}
			Iterator<Map.Entry<String, String>> wlentries =  Utils.whitelistHM.entrySet().iterator();
			while (wlentries.hasNext()) {
				Map.Entry<String, String> entry = wlentries.next();
				String key = entry.getKey();
				if (key != null && !Utils.auditHM.containsKey(key)) {
					String curTS = Utils.currentTimeFromSystem();
					Utils.auditHM.put(key, curTS);
					alog.info("ADDING blocked entry: " + key +", at: "+curTS);
				}
			}
		} catch (Exception e) {
			slog.error("auditWhiteList error/exception: "+e.getMessage());
		}
		for (Map.Entry<String, String> entry : Utils.auditHM.entrySet()) {
			slog.info("AuditHM entries: "+ entry.getKey() + ", " + entry.getValue());
		}
		
	}
	
	
	public static void logAuditTrail(String type) {
		synchronized(auditHM) {
			Iterator<Map.Entry<String, String>> entries = auditHM.entrySet().iterator();
			while (entries.hasNext()) {
			    Map.Entry<String, String> entry = entries.next();
			    if (entry.getValue().equals(Utils.MD5))
			    	auditHM.remove(entry.getKey());
			    else if (entry.getValue().equals(MURL))
			    	auditHM.remove(entry.getKey());
			}
		}
	}
	
	
	public static boolean skipThisUrl(String blockedEntry, String timestamp) {
		boolean skip = false;
		if (Utils.getWhitelistHM().containsKey(blockedEntry)) {
			skip = true;
			slog.info("--> skipping entry as whitelist contains malicious URL/MD5: " + blockedEntry + ", timestamp: " + timestamp);
		}
		else {
			slog.info("----> adding/removing malicious URL/MD5: " + blockedEntry + ", timestamp: " + timestamp);
		}
		return skip;
	}
	
	public static String formatClamEntry(String md5Hash, String malwareName) {
		StringBuilder sb = new StringBuilder(SB_SIZE);
		sb.append(md5Hash).append(":*:").append(malwareName).append(":");
		return sb.toString();
	}
	
	public static int write(MurlDTO dto) {
		int val = 0;
		if (!dto.getContent().isEmpty()) {
			val = write2File(dto.getFileName(), Utils.decodeURL(dto.getContent().toJSONString()));
			////Utils.logAuditTrail(MURL);
		}
		else
			val = write2File(dto.getFileName(), "");
		return val;
	}
	
	public static String decodeURL(String encodeURL) {
		String ret = null;
		try {
			ret = encodeURL.replaceAll("\\\\", "");
			slog.debug("replacing escaped URL "+encodeURL + " with regular URL--> "+ ret);
		} catch (Exception e) {
			slog.error(e.getMessage());
		}
		return ret;
	}
	
	
	public static int write2File(String filename, String obj) {
		int val = 1;
		FileWriter file = null;
		try { 
			file = new FileWriter(filename);
			file.write(obj);
			file.flush();
			val = obj.length();
			slog.info("Utils.write2file() content: \n" + obj + ", len: " + val);
		} catch (IOException e) {
			val = 0;
			slog.info("Utils.write2file() exception: " + e.toString());
		}
		finally {
			if (file != null)
				try {
					file.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
		return val;
	}
	*/
	
	/*private static int writeFop(String filename, String content) {
		
		int retVal = 0;
		File file = new File(filename);
		boolean created = false;
		FileOutputStream fop=null;
		
		try {
			fop = new FileOutputStream(file);
			// if file doesn't exists then create it, if file exists remove it
			if (!file.exists()) {
				created = file.createNewFile();
				if (created)
					slog.debug("Created file since file did not exist: " + file.toString());
			} else if (file.exists()) {
				boolean deleted = file.delete();
				if (deleted) {
					slog.debug("Deleted file: "+file.toString());
					created = file.createNewFile();
					if (created)
						slog.debug("Created file: "+file.toString());
				}
			}
			// get the content in bytes
			byte[] contentInBytes = content.getBytes();
	
			fop.write(contentInBytes);
			fop.flush();
			fop.close();
			retVal = contentInBytes.length;
					
			slog.info("Utils.write2File(): " + retVal +" bytes written, content: "+contentInBytes.toString());
	
		} catch (IOException e) {
			retVal = 0;
			slog.info(e.getMessage());
		} finally {
			if (file != null)
				file = null;
			if (fop != null)
				try {
					fop.close();
				} catch (IOException e) {
					slog.info("Utils.write2File() error closing file descriptors: " + e.getMessage());
				}
		}
		return retVal;
	}*/
	
	/*
	public static String getBody(HttpServletRequest request) throws IOException {

	    String body = null;
	    StringBuilder stringBuilder = new StringBuilder();
	    BufferedReader bufferedReader = null;

	    try {
	        InputStream inputStream = request.getInputStream();
	        if (inputStream != null) {
	            bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
	            char[] charBuffer = new char[128];
	            int bytesRead = -1;
	            while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
	                stringBuilder.append(charBuffer, 0, bytesRead);
	            }
	        } else {
	            stringBuilder.append("");
	        }
	    } catch (IOException ex) {
	        throw ex;
	    } finally {
	        if (bufferedReader != null) {
	            try {
	                bufferedReader.close();
	            } catch (IOException ex) {
	                throw ex;
	            }
	        }
	    }

	    body = stringBuilder.toString();
	    return body;
	}

	public static Map<String, String> getHm() {
		return hm;
	}

	public static void setHm (Map<String, String> hm) {
		Utils.hm = hm;
	}

	public static String getPropertyFile() {
		return propertyFile;
	}

	public static void setPropertyFile(String propertyFile) {
		Utils.propertyFile = propertyFile;
	}*/
	
	public static String getKeyStoreFilePath() {
		return keyStoreFilePath;
	}

	public static void setKeyStoreFilePath(String keyStoreFilePath) {
		Utils.keyStoreFilePath = keyStoreFilePath;
	}

	public static String getKeyStorePasswordFilePath() {
		return keyStorePasswordFilePath;
	}

	public static void setKeyStorePasswordFilePath(String keyStorePasswordFilePath) {
		Utils.keyStorePasswordFilePath = keyStorePasswordFilePath;
	}

	public static String getMySqlConfigFile() {
		return mySqlConfigFile;
	}
	/*
	public static Map<String, String> getWhitelistHM() {
		return whitelistHM;
	}

	public static void setWhitelistHM(Map<String, String> whitelistHM) {
			Utils.whitelistHM = whitelistHM;
	}

	public static Map<String, String> getAuditHM() {
		return auditHM;
	}

	public static void setAuditHM(Map<String, String> auditHM) {
		Utils.auditHM = auditHM;
	}

	public static Boolean getIncrementalUpdatesOnly() {
		return ISProperties.getPropertiesDTO().getIncrementalUpdatesOnly();
	}

	public static void setIncrementalUpdatesOnly(Boolean incrementalUpdatesOnly) {
		Utils.incrementalUpdatesOnly = incrementalUpdatesOnly;
	}*/

	/**
	 * @return the authorizationPropertyFileName
	 */
	public static String getAuthorizationPropertyFileName() {
		return authorizationPropertyFileName;
	}

	/**
	 * @param authorizationPropertyFileName the authorizationPropertyFileName to set
	 */
	public static void setAuthorizationPropertyFileName(
			String authorizationPropertyFileName) {
		Utils.authorizationPropertyFileName = authorizationPropertyFileName;
	}

	/**
	 * @return the authorizationPropertyFile
	 */
	public static String getAuthorizationPropertyFile() {
		return authorizationPropertyFile;
	}

	/**
	 * @param authorizationPropertyFile the authorizationPropertyFile to set
	 */
	public static void setAuthorizationPropertyFile(String authorizationPropertyFile) {
		Utils.authorizationPropertyFile = authorizationPropertyFile;
	}
	
}
