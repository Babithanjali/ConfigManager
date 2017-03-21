package com.src.dbaccess;

//import java.text.SimpleDateFormat;
//import java.util.Date;

import org.apache.log4j.Logger;

public class DbDebugLog {

	public static void logDbInfo(String adapterName, String className, String methodName, String restStr) {
	
		Logger slog = Logger.getLogger("ServerLog");
		
//		String strThreadName = Thread.currentThread().getName();
//		if (null == strThreadName) {
//			strThreadName = "<No_Thread_Name>";
//		}
		
		//SimpleDateFormat dateFormat3 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		//String dateStr = dateFormat3.format(new Date());
		//System.out.println(String.format("%s %s DB_DEBUG - [%s / %s / %s] - %s", dateStr, strThreadName, adapterName, className, methodName, restStr));
		String strDebugMsg = String.format("[%s / %s / %s] DB_DEBUG - %s %n", adapterName, className, methodName, restStr);
		slog.info(strDebugMsg);
	}
}
