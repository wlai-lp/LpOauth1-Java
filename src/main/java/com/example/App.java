package com.example;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * 
     * @param args The arguments of the program.
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        System.out.println("Hello World!");

        // load properties
        File configFile = new File("config.properties");
        FileReader reader = new FileReader(configFile);
        Properties props = new Properties();
        // load the properties file:
        props.load(reader);

        // Oauth1
        OAuthService service = new ServiceBuilder()
                .provider(EHAPI.class)
                .apiKey(props.getProperty(
                        "apiKey"))
                .apiSecret(props.getProperty(
                        "apiSecret"))
                .build();
        // OAuth token, you will need to fill in your token & secret
        Token accessToken = new Token(props.getProperty(
                "token"),
                props.getProperty("tokenSecret"));
        // Create the OAuth request, you will need to update the following:
        // {BASE URI} - with your domain
        // {YOUR ACCOUNT NUMBER} - with your account number
        OAuthRequest request = new OAuthRequest(Verb.POST,
                "https://va.msghist.liveperson.net/messaging_history/api/account/" + props.getProperty("siteId")
                        + "/conversations/search?offset=0&limit=50");
        request.addHeader("Content-Type", "application/json");
        // body parameters that you would like to add to the api call
        request.addPayload("{\"start\":{\"from\":1667325500000,\"to\":1667325607365}}");
        // sign the request
        service.signRequest(accessToken, request);
        Response response = request.send();
        // print the response to the console
        System.out.println(response.getBody());

        System.out.println("done!");

    }
}
