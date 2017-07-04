package com.onchain.webservice.toolkit;

import com.onchain.webservice.toolkit.client.JdkHttpResourceEntrance;
import com.onchain.webservice.toolkit.keytools.KeyTools;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by xiaom on 2017/3/27.
 */
public class OauthRegister {

    public static void main(String[] args){
        ConfigManager.init();

        if  (Const.OAUTH_URL == null || Const.OAUTH_URL.equals("")) {
            System.out.println("OAUTH_URL is not configured");
            return;
        }
        if  (Const.CERT_FILE_PATH == null || Const.CERT_FILE_PATH.equals("")) {
            System.out.println("CERT_FILE_PATH is not configured");
            return;
        }

        try {
            //生成CAKEY
            String caKey = null;
            if ( Const.CERT_TYPE != null )
                caKey = KeyTools.getPubKeyHashFromCertFile(Const.CERT_FILE_PATH,Const.CERT_TYPE);
            else
                caKey = KeyTools.getPubKeyHashFromCertFile(Const.CERT_FILE_PATH);

            //发起初始化OAuth Server
            Map<String, String> params = new HashMap<String , String>();
            params.put("cakey",caKey);
            String result = JdkHttpResourceEntrance.postJson(Const.OAUTH_URL, params);
            System.out.println(result);
        }catch(FileNotFoundException ex){
            System.out.println("CERT_FILE_PATH is not valid,or file not exist");
        }catch(IOException ex){
            ex.printStackTrace();
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
