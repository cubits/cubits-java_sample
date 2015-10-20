
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.net.HttpURLConnection;
import java.net.URL;

import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import javax.net.ssl.HttpsURLConnection;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

class CubitsPay
{
	public static String cubits_key;
	public static String cubits_secret;
	public static String cubits_url = "https://pay.cubits.com";
	public static HttpURLConnection con;
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	/*
	 * Seting all important request headers and additional information
	 */
	public static void setup_request(String host, String path, String key, String secret) throws InvalidKeyException, NoSuchAlgorithmException, MalformedURLException, IOException{
		cubits_key = key;
		cubits_secret = secret;

		URL obj = new URL(host + path);
		con = (HttpURLConnection) obj.openConnection();

		con.setRequestProperty("Accept", "application/vnd.api+json");
		con.setRequestProperty("X-Cubits-Key", cubits_key);
		String nonce = calc_nonce();
		con.setRequestProperty("X-Cubits-Nonce", nonce);
		con.setRequestProperty("X-Cubits-Signature", calc_signature(path, nonce, ""));

	}

	/*
	 * Simple nonce calculation with timestamp
	 */
	public static String calc_nonce(){
		return String.valueOf(System.currentTimeMillis());
	}

	public static String calc_signature(String path, String nonce, String request_data) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, UnsupportedEncodingException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(request_data.getBytes("UTF-8"));

		String sha256_msg = bytesToHex(digest);
		String msg = path + nonce + sha256_msg;

		SecretKeySpec secretkey = new SecretKeySpec(cubits_secret.getBytes("UTF-8"), "HmacSHA512");
		Mac sha512_HMAC = Mac.getInstance("HmacSHA512");
		sha512_HMAC.init(secretkey);
		byte[] mac_data = sha512_HMAC.doFinal(msg.getBytes("UTF-8"));

		String hmac_sha512_signature = bytesToHex(mac_data);
		System.out.println(String.format("Computed Msg.: %s", msg));
		System.out.println(String.format("Computed Signature: %s", hmac_sha512_signature));
		return hmac_sha512_signature;
	}

	/*
	 * Main programm execution.
	 */
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException
	{
		StringBuffer response = new StringBuffer();
		System.out.println("key: " + args[0]);
		System.out.println("secret: " + args[1]);
		setup_request(cubits_url, "/api/v1/test", args[0], args[1]);
		String inputLine;
		BufferedReader in;
		try{
			in = new BufferedReader(
			        new InputStreamReader(con.getInputStream()));
		} catch(Exception e) {
			in = new BufferedReader(
			        new InputStreamReader(con.getErrorStream()));
			System.out.println("Error: " + e.getMessage());
		}

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		int responseCode = con.getResponseCode();
		System.out.println("Response Code : " + responseCode);

		//print result
		System.out.println(response.toString());
	}

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars).toLowerCase();
	}
}
