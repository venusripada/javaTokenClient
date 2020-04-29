import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import company.okta.helper.TokenProvider;
import company.okta.helper.TokenProviderImpl;

public class ExampleUsage {
    public static void main(String[] args) throws IOException, KeyManagementException, NoSuchAlgorithmException {
        TokenProvider tokenProvider = new TokenProviderImpl("https://<okta-url>/oauth2/default",
                "<clientid>",
                "<client secret>",
                "<scopes>");
        String token = tokenProvider.getAccessToken();
        System.out.println(token);
         token = tokenProvider.getAccessToken();
        System.out.println(token);

    }
}
