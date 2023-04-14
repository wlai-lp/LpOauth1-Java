package com.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

public class OAuthAuthenticator {
    private String domain;
    private String path;
    private String appKey;
    private String secret;
    private String accessToken;
    private String accessTokenSecret;

    public static void main(String[] args) throws IOException {

        // load properties
        File configFile = new File("config.properties");
        FileReader reader = new FileReader(configFile);
        Properties props = new Properties();
        // load the properties file:
        props.load(reader);

        String domain = "va.msghist.liveperson.net/messaging_history";
        // Insert the path without the query string:
        // "/api/account/:accountId/eligibility"
        String path = "/api/account/" + props.getProperty("siteId") +
                "/conversations/search";

        String appKey = props.getProperty("apiKey");
        String secret = props.getProperty("apiSecret");
        String accessToken = props.getProperty("token");
        String accessTokenSecret = props.getProperty("tokenSecret");
        // Insert query string as an array
        String[] parameterList = { "offset=0", "limit=50" };
        OAuthAuthenticator generator = new OAuthAuthenticator(domain, path, appKey, secret, accessToken,
                accessTokenSecret);
        String result = generator.generateOauthHeader("POST", parameterList);
        System.out.println(result);

        // note, this uses unitrest library, you can sub it for whatever you have
        try {
            // sendRequest(result);
            sendJavaRequest(result);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private static void sendJavaRequest(String header) throws IOException {
        URL url = new URL(
                "https://va.msghist.liveperson.net/messaging_history/api/account/28079266/conversations/search?offset=0&limit=50");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setDoOutput(true);

        con.setRequestProperty("Content-Type", "application/json");
        con.setRequestProperty("Authorization", header);

        String jsonInputString = "{\"start\":{\"from\":1667325500000,\"to\":1667325607365}}";
        try (OutputStream os = con.getOutputStream()) {
            byte[] input = jsonInputString.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(con.getInputStream(), "utf-8"))) {
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            System.out.println(response.toString());
        }

    }

    private static void sendRequest(String header) throws UnirestException {
        Unirest.setTimeouts(0, 0);
        com.mashape.unirest.http.HttpResponse<String> response = Unirest.post(
                "https://va.msghist.liveperson.net/messaging_history/api/account/28079266/conversations/search?offset=0&limit=50")
                .header("Content-Type", "application/json")
                .header("Authorization", header)
                .body("{\"start\":{\"from\":1667325500000,\"to\":1667325607365}}")
                .asString();

        System.out.println(response.getBody());
    }

    public OAuthAuthenticator(String domain,
            String path,
            String appKey,
            String secret,
            String accessToken,
            String accessTokenSecret) {
        this.domain = domain;
        this.path = path;
        this.appKey = appKey;
        this.secret = secret;
        this.accessToken = accessToken;
        this.accessTokenSecret = accessTokenSecret;
    }

    public String generateOauthHeader(String method,
            String[] additionalParameters) {
        long timestamp = new Date().getTime() / 1000;
        String nonce = getNonce();

        ArrayList<String> parameters = new ArrayList<String>();
        parameters.add("oauth_consumer_key=" + appKey);
        parameters.add("oauth_nonce=" + nonce);
        parameters.add("oauth_signature_method=HMAC-SHA1");
        parameters.add("oauth_timestamp=" + timestamp);
        if (accessToken != null) {
            parameters.add("oauth_token=" + accessToken);
        }
        parameters.add("oauth_version=1.0");
        if (additionalParameters != null) {
            for (String additionalParameter : additionalParameters) {
                parameters.add(additionalParameter);
            }
        }
        Collections.sort(parameters);
        StringBuffer parametersList = new StringBuffer();
        for (int i = 0; i < parameters.size(); i++) {
            parametersList.append(((i > 0) ? "&" : "") + parameters.get(i));
        }
        String signatureString = method + "&" +
                URLEncoder.encode("https://" + domain + path) + "&" +
                URLEncoder.encode(parametersList.toString());
        String signature = null;
        try {
            SecretKeySpec signingKey = new SecretKeySpec((secret + "&"
                    + (accessTokenSecret == null ? "" : accessTokenSecret)).getBytes(), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            byte[] rawHMAC = mac.doFinal(signatureString.getBytes());
            signature = Base64.getEncoder().encodeToString(rawHMAC);
        } catch (Exception e) {
            System.err.println("Unable to append signature");
            System.exit(0);
        }
        String authorizationLine = "OAuth " +
                "oauth_consumer_key=\"" + appKey + "\", " +
                "oauth_nonce=\"" + nonce + "\", " +
                "oauth_timestamp=\"" + timestamp + "\", " +
                "oauth_signature_method=\"HMAC-SHA1\", " +
                "oauth_signature=\"" + URLEncoder.encode(signature) + "\", " +
                "oauth_version=\"1.0\"";
        if (accessToken != null) {
            authorizationLine += ", oauth_token=\"" + accessToken + "\"";
        }
        return authorizationLine;
    }

    public String getNonce() {
        int leftLimit = 48;
        int rightLimit = 122;
        int targetStringLength = 10;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }
}