// code from https://developers.liveperson.com/connect-to-messaging-api.html#details-on-authorization

package com.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
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

        String domain = "https://va.msghist.liveperson.net/messaging_history";
        // Insert the path without the query string:
        // "/api/account/:accountId/eligibility"
        String path = "/api/account/" + props.getProperty("siteId") + "/conversations/search?";
        String appKey = props.getProperty("apiKey");
        String secret = props.getProperty("apiSecret");
        String accessToken = props.getProperty("token");
        String accessTokenSecret = props.getProperty("tokenSecret");
        // Insert query string as an array
        String[] parameterList = { "offset=0", "limit=50" };
        OAuthAuthenticator generator = new OAuthAuthenticator(domain, path, appKey, secret, accessToken,
                accessTokenSecret);
        String result = generator.generateOauthHeader("POST", parameterList);
        System.out.println("result");
        System.out.println(result);
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