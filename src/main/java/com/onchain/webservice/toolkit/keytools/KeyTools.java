package com.onchain.webservice.toolkit.keytools;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

public class KeyTools {

	private static final String CERT_FILE_TYPE_PEM = ".pem";
	private static final String CERT_FILE_TYPE_CER = ".cer";
	private static final String CERT_FILE_TYPE_CRT = ".crt";

	// 通过文件生成CAKey，默认使用pem格式进行解析
	public static String getPubKeyHashFromCertFile(String certFilePath) throws FileNotFoundException,IOException {
		return getPubKeyHashFromCertFile(certFilePath,CERT_FILE_TYPE_PEM);
	}

	// 通过文件生成CAKey
	public static String getPubKeyHashFromCertFile(String certFilePath,String fileType) throws FileNotFoundException,IOException {
		try {
			PublicKey publicKey = null;
			if ( fileType.equals(CERT_FILE_TYPE_PEM)) {

				publicKey = getPubKeyObjFromPemFile(certFilePath);

			}else if (fileType.equals(CERT_FILE_TYPE_CER) || fileType.equals(CERT_FILE_TYPE_CRT) ) {

				publicKey = getPubKeyObjFromCertFile(certFilePath);

			}else{
				return null;
			}
			return Digest.toScriptHash(publicKey.getEncoded()).toString();


		}catch(FileNotFoundException ex){
			throw ex;
		}catch(IOException ex){
			throw ex;
		}
	}


	// 通过Pem文件生成PubKey对象
	public static PublicKey getPubKeyObjFromPemFile(String pemFilePath) throws FileNotFoundException,IOException {
		try {
			FileInputStream in = new FileInputStream(pemFilePath);
			byte[] certFileBytes = new byte[in.available()];
			in.read(certFileBytes);
			in.close();
			String input = new String(certFileBytes, "UTF-8");
			String certTxt = input.replaceAll("(-+BEGIN CERTIFICATE-+\\r?\\n|-+END CERTIFICATE-+\\r?\\n?)", "");
			System.out.println(certTxt);

			// don't use this for real projects!
			BASE64Decoder decoder = new BASE64Decoder();
			byte[] certBytes = decoder.decodeBuffer(certTxt);

			// generate public key
			X509Certificate cert = X509Certificate.getInstance(certBytes);
			PublicKey publicKey = cert.getPublicKey();
			return publicKey;

		}catch(FileNotFoundException ex){
			throw ex;
		}catch(IOException ex){
			throw ex;
		}
		catch(Exception ex){
			ex.printStackTrace();
			return null;
		}
	}



	// 通过cer文件生成PubKey对象
	public static PublicKey getPubKeyObjFromCertFile(String filePath) throws FileNotFoundException,IOException {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			File file = new File(filePath);
			InputStream inStream = new FileInputStream(file);
			java.security.cert.X509Certificate oCert = (java.security.cert.X509Certificate) cf.generateCertificate(inStream);
			inStream.close();
			PublicKey publicKey = oCert.getPublicKey();

			return publicKey;

		}catch(FileNotFoundException ex){
			throw ex;
		}catch(IOException ex){
			throw ex;
		}catch(Exception ex){
			ex.printStackTrace();
			return null;
		}
	}

	// 通过PUBLIC KEY字符串生成PubKey对象
	public static PublicKey getPubKeyObjFromKeyStr(String input) {
		try {
			String pubKey = input.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
			System.out.println(pubKey);

			// don't use this for real projects!
			BASE64Decoder decoder = new BASE64Decoder();
			byte[] keyBytes = decoder.decodeBuffer(pubKey);

			// generate public key
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(spec);
			return publicKey;

		}catch(Exception ex){
			ex.printStackTrace();
			return null;
		}
	}

	// 通过PUBLIC KEY字符串生成CAKey
	private static String getPubKeyHashFromKey(String input) {
		PublicKey publicKey = getPubKeyObjFromKeyStr(input);
		byte[] hashVal = Digest.sha256(publicKey.getEncoded());
		return toHexString(hashVal) ;
	}

	private static String toHexString(byte[] value) {
		StringBuilder sb = new StringBuilder();
		byte[] var2 = value;
		int var3 = value.length;

		for(int var4 = 0; var4 < var3; ++var4) {
			byte b = var2[var4];
			int v = Byte.toUnsignedInt(b);
			sb.append(Integer.toHexString(v >>> 4));
			sb.append(Integer.toHexString(v & 15));
		}

		return sb.toString();
	}

	public static void main(String[] args) {

		try{
//			String input ="-----BEGIN CERTIFICATE-----\n" +
//					"MIIE8jCCA9qgAwIBAgIQXYF4aOyiIJ3Cr4VH2yAQ3DANBgkqhkiG9w0BAQsFADBP\n" +
//					"MQswCQYDVQQGEwJDTjEaMBgGA1UEChMRV29TaWduIENBIExpbWl0ZWQxJDAiBgNV\n" +
//					"BAMMG0NBIOayg+mAmuWFjei0uVNTTOivgeS5piBHMjAeFw0xNjA2MDEwMTA0NTla\n" +
//					"Fw0xNzA2MDEwMTA0NTlaMBsxGTAXBgNVBAMMEHd3dy45MXh1bmh1aS5jb20wggEi\n" +
//					"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCJ6SG/3P8Hcy9sVlAKvdcFcTrj\n" +
//					"iB3An1Le4mxqLNSwweifFGDvAfsXMgnxanOWtj32T0N0iv+W8/KPYu9Y5itwEneq\n" +
//					"JHdpwHmhgleyvg/STr3rlAdM9P/BmxBAydG7CgQjAq+VTmwbLhVzBN4eEjJHabqv\n" +
//					"LqVSIzX8h7J14uuFABrtoFx8buzwC1Dn1/t/3eIaVOAXxNY94P+VQbtwpHLMvRRJ\n" +
//					"FuhbtCBRdJ4OEadVopiSJqGG3imzQfHEuPDxpNOUMLkJ9EViHsWdotFWFhD4Tg9U\n" +
//					"FBSkXFVPssN6XNxLKj0sH2XV7ZoRuyQdfoWzpM7H9CdZd4F27Lo9HEyhYjlVAgMB\n" +
//					"AAGjggH8MIIB+DAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\n" +
//					"CCsGAQUFBwMBMAkGA1UdEwQCMAAwHQYDVR0OBBYEFJeuSayE6+PDZxkxl0Tywmxz\n" +
//					"y2djMB8GA1UdIwQYMBaAFDDadIbzKJBWntcxMcK9Wc2TEjkdMH8GCCsGAQUFBwEB\n" +
//					"BHMwcTA1BggrBgEFBQcwAYYpaHR0cDovL29jc3AyLndvc2lnbi5jbi9jYTJnMi9z\n" +
//					"ZXJ2ZXIxL2ZyZWUwOAYIKwYBBQUHMAKGLGh0dHA6Ly9haWEyLndvc2lnbi5jbi9j\n" +
//					"YTJnMi5zZXJ2ZXIxLmZyZWUuY2VyMD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6Ly9j\n" +
//					"cmxzMi53b3NpZ24uY24vY2EyZzItc2VydmVyMS1mcmVlLmNybDBqBgNVHREEYzBh\n" +
//					"ghB3d3cuOTF4dW5odWkuY29tghVmaW50b29scy45MXh1bmh1aS5jb22CEGNtcy45\n" +
//					"MXh1bmh1aS5jb22CEHByby45MXh1bmh1aS5jb22CEnByaWNlLjkxeHVuaHVpLmNv\n" +
//					"bTBPBgNVHSAESDBGMAgGBmeBDAECATA6BgsrBgEEAYKbUQEBAjArMCkGCCsGAQUF\n" +
//					"BwIBFh1odHRwOi8vd3d3Lndvc2lnbi5jb20vcG9saWN5LzANBgkqhkiG9w0BAQsF\n" +
//					"AAOCAQEAvVeRH/QPezMTdRYAW6+L4GJQVQNWMHbQSIQTffA7qlHy3DfyxQFLjpYJ\n" +
//					"B770s5uDxv1PKlokJckCBAMd9d2BzMB9qozRT5PckTj1Py6azYIGr3OWBXcIl+WW\n" +
//					"MKGSgRu78iwhewFLMAw8lGV1py/QrFYFOsX7kY5Y/2h/VPxp6xMN33SlYd3o8IXY\n" +
//					"DhCL3dYnCKnFTJph1cUvjdHrd766pREAcpKZS26Go9OgDu0J0zp/bQyKGfbXEAUg\n" +
//					"rgZP6xQkEMsJxvkjnsiXncPMK7SewejuebRz7nuGD4YykhCCynM/MDwd6JlGMto9\n" +
//					"laXTEPnmd7WQFToQt0L0rfsynHO7Xw==\n" +
//					"-----END CERTIFICATE-----";
//
//			System.out.println("HASH:"+ getPubKeyHashFromCert(input) );


			System.out.println("HASH:"+toHexString(Digest.sha256(getPubKeyObjFromCertFile("D:\\FDD.cer").getEncoded())));

		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
}
