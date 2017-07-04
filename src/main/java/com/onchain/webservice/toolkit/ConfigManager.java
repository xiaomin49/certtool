package com.onchain.webservice.toolkit;




import java.io.*;
import java.util.Arrays;
import java.util.Properties;

/**
 * 配置文件初始化类
 * 
 * @author 12146
 *
 */
public class ConfigManager {

	static String cfgFile = "./config.properties";

    public static void init() {
        init(cfgFile);
    }

	
	
	public static void init(String cfg) {
		System.out.println("init Config,path="+cfg);
		initParam(cfg);
		
	}


	
	private static void initParam(String cfgFile) {
		Properties prop = new Properties();
		try (InputStream in = new FileInputStream(cfgFile)){
			prop.load(in);

			Const.OAUTH_URL = prop.getProperty("OAUTH_URL");
			Const.CERT_FILE_PATH = prop.getProperty("CERT_FILE_PATH");
			Const.CERT_TYPE = prop.getProperty("CERT_TYPE");


		} catch (IOException e ) {
			e.printStackTrace();
			//logger.error("Failed to initParam,cause:"+e.getMessage(), e);
		}
	}




}
