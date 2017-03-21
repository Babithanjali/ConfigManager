package com.src.common;

import java.util.Properties;

public class PropertiesData {
	private static Properties prop = new Properties();
	
	public static Properties getPropertiesFile(){
		return prop;
	}
	
	public static void setProperty(String key, String value){
		prop.setProperty(key, value);
	}
	
	public static String getProperty(String key){
		return prop.getProperty(key);
	}
	
	public static String getProperty(String key, String defaultValue){
		return prop.getProperty(key, defaultValue);
	}
	
	public static boolean containsKey(String key){
		return prop.containsKey(key);
	}
}