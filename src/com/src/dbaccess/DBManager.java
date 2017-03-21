package com.src.dbaccess;

import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import main.java.configManager.ConfigManager;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import com.src.utils.Utils;

public class DBManager {

	private static Logger slog = Logger.getLogger("ServerLog");
	
	public static Connection getConnectionToDB() {
		slog.info("[AuthenticationConfig / DBManager / getConnectionToDB] Attempting to connect to the database...");
		
		String MYSQL_DRIVER = "com.mysql.jdbc.Driver";
		Properties mySqlProp = readMySqlConfig();
		Connection DBManagerionObject = null;
		
		try {
			// Load mysql DB driver
			String connectionURL = null;
			String sqlUser = null;
			String sqlPwd = null;
			if (mySqlProp.getProperty("connectionURL") != null){
				connectionURL = ConfigManager.decodeString(mySqlProp.getProperty("connectionURL"));
			}
			if (mySqlProp.getProperty("dbUser") != null){
				sqlUser = ConfigManager.decodeString(mySqlProp.getProperty("dbUser"));
			}
			if (mySqlProp.getProperty("connectionURL") != null){
				sqlPwd = mySqlProp.getProperty("dbPassword");
			}
			
			Class.forName(MYSQL_DRIVER).newInstance();
			//Get a Connection to the database
			DBManagerionObject = DriverManager.getConnection(connectionURL, sqlUser, sqlPwd); 
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] SQLException occured while obtaining database connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / getConnectionToDB] SQLException occured while obtaining database connection. Stack trace is - ", ex);
			return null;
		} 		
		catch (InstantiationException ex) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] InstantiationException occured while obtaining database connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / getConnectionToDB] InstantiationException occured while obtaining database connection. Stack trace is - ", ex);
			return null;
		} 
		catch (IllegalAccessException ex) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] IllegalAccessException occured while obtaining database connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / getConnectionToDB] IllegalAccessException occured while obtaining database connection. Stack trace is - ", ex);
			return null;
		} 
		catch (ClassNotFoundException ex) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] ClassNotFoundException occured while obtaining database connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / getConnectionToDB] ClassNotFoundException occured while obtaining database connection. Stack trace is - ", ex);
			return null;
		} 
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] Exception occured while obtaining database connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / getConnectionToDB] Exception occured while obtaining database connection. Stack trace is - ", ex);
		} 
		
		if (null == DBManagerionObject) {
			slog.error("[DBAccess / DBManager / getConnectionToDB] Obtaining database connection returned null object. Returning null");
			return null;
		}

		slog.info("[DBAccess / DBManager / getConnectionToDB] Successfully obtained the database connection. Returning the database connection object");		
		return DBManagerionObject;
	}
	
	private static Properties readMySqlConfig(){

		FileInputStream fop = null; 
		Properties mySqlProp = new Properties();
		try {
			fop = new FileInputStream(Utils.getMySqlConfigFile());
			mySqlProp.load(fop);
			String dbPassword  = ConfigManager.decryptMySqlPassword(mySqlProp.getProperty("dbPassword"), Base64.decodeBase64(mySqlProp.getProperty("salt")));
			mySqlProp.setProperty("dbPassword", dbPassword);
		}catch (Exception exc){
			slog.error("[DBAccess / DBManager / readMySqlConfig] Exception occured while reading mysql config properties. Exception is - " + exc.getMessage());				
			return null;
		}
		return mySqlProp;
	}
	
	public static boolean closeConnectionToDB(Connection DBManagerion) {
		if (null == DBManagerion) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] Connection object is null. Returning failure");
			return false;
		}

		slog.info("[DBAccess / DBManager / closeConnectionToDB] Checking if the connection object has already been closed...");
		
		try
		{
			if (true == DBManagerion.isClosed()) {
				slog.info("[DBAccess / DBManager / closeConnectionToDB] Connection object has already been closed before. Returning success");
				DBManagerion = null;
				return true;		
			}
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking if the database connection has already been closed. Returning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking if the database connection has already been closed. Returning failure. Stack trace is - ", ex);
			DBManagerion = null;
			return false;
		} 		
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] Exception occured while checking if the database connection has already been closed. Returning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] Exception occured while checking if the database connection has already been closed. Returning failure. Stack trace is - ", ex);
			DBManagerion = null;
			return false;
		} 		

		slog.info("[DBAccess / DBManager / closeConnectionToDB] Checking if the connection needs to be commited before closing...");
		
		try
		{
			if (false == DBManagerion.getAutoCommit()) {
				//only call commit, if we are NOT already in auto-commit mode
				DBManagerion.commit();
			}
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking the commit mode and commiting the connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking the commit mode and commiting the connection. Stack trace is - ", ex);
			//We do not return here as we still try to go ahead and close the db connection
		} 		
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking the commit mode and commiting the connection. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while checking the commit mode and commiting the connection. Stack trace is - ", ex);
			//We do not return here as we still try to go ahead and close the db connection
		} 		

		slog.info("[DBAccess / DBManager / closeConnectionToDB] Attempting to close the connection...");
		
		try
		{
			DBManagerion.close();
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while closing the connection. Retuning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] SQLException occured while closing the connection. Retuning failure. Stack trace is - ", ex);
			DBManagerion = null;
			return false;
		} 		
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / closeConnectionToDB] Exception occured while closing the connection. Retuning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeConnectionToDB] Exception occured while closing the connection. Retuning failure. Stack trace is - ", ex);
			DBManagerion = null;
			return false;
		} 		
		
		DBManagerion = null;
		
		slog.info("[DBAccess / DBManager / closeConnectionToDB] Successfully closed the connection. Returning success...");
		return true;
	}
	
	public static boolean closeStatement(Statement statementObj)
	{
		if (null == statementObj) {
			slog.error("[DBAccess / DBManager / closeStatement] Statement object is null. Returning failure");
			return false;			
		}
		
		slog.info("[DBAccess / DBManager / closeStatement] Checking if the statement object has already been closed...");
		
		try
		{
			if (true == statementObj.isClosed()) {
				slog.info("[DBAccess / DBManager / closeStatement] Statement object has already been closed before. Returning success");
				statementObj = null;
				return true;		
			}
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / closeStatement] SQLException occured while checking if the statement has already been closed. Returning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeStatement] SQLException occured while checking if the statement has already been closed. Returning failure. Stack trace is - ", ex);
			statementObj = null;
			return false;
		} 		
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / closeStatement] Exception occured while checking if the statement has already been closed. Returning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeStatement] Exception occured while checking if the statement has already been closed. Returning failure. Stack trace is - ", ex);
			statementObj = null;
			return false;
		} 		
		
		slog.info("[DBAccess / DBManager / closeStatement] Attempting to close the statement ...");
		
		try
		{
			statementObj.close();
		}
		catch (SQLException ex) {
			slog.error("[DBAccess / DBManager / closeStatement] SQLException occured while closing the statement. Retuning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeStatement] SQLException occured while closing the statement. Retuning failure. Stack trace is - ", ex);
			statementObj = null;
			return false;
		} 		
		catch (Exception ex) {
			slog.error("[DBAccess / DBManager / closeStatement] Exception occured while closing the statement. Retuning failure. Exception is - " + ex.getMessage());
			slog.error("[DBAccess / DBManager / closeStatement] Exception occured while closing the statement. Retuning failure. Stack trace is - ", ex);
			statementObj = null;
			return false;
		} 		
		
		statementObj = null;
		
		slog.info("[DBAccess / DBManager / closeStatement] Successfully closed the statement. Returning success...");
		
		return true;
	}
	
	
}
