package company.okta.helper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;


public class TokenProviderImpl implements TokenProvider {
    private final String clientID;
    private final String clientSecret;
    private Date expiresIn;
    private static String accessToken;
    private final String tenantURL;
    private final String scope;
    Logger logger = Logger.getLogger(TokenProviderImpl.class.getName());

    public TokenProviderImpl(String tenantURL, String clientID, String clientSecret, String scope) {
        this.clientID = clientID;
        this.clientSecret = clientSecret;
        this.tenantURL = tenantURL;
        this.scope = scope;
    }

    private URL createConnectionURL(String tenantURL) throws MalformedURLException {
        String absUrl = String.format("%s%s",tenantURL,"/v1/token");
        logger.info(String.format("absolute url %s",absUrl));
        return new URL(absUrl);
    }

    private String getBasicAuthEncoding(String clientID, String  clientSecret) throws UnsupportedEncodingException {
        String clientIDAndSecret = clientID+":"+clientSecret;
        byte[] message = clientIDAndSecret.getBytes("UTF-8");
        return DatatypeConverter.printBase64Binary(message);

    }
    private HttpURLConnection getConnection(URL tenantURL,String basicAuth) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        HttpsURLConnection con = (HttpsURLConnection) tenantURL.openConnection();
        SSLContext sc = SSLContext.getInstance("TLSv1.2");
        sc.init(null, null, new java.security.SecureRandom());
        con.setSSLSocketFactory(sc.getSocketFactory());
        con.setRequestMethod("POST");
        con.setRequestProperty("Accept", "application/json");
        con.setRequestProperty("Accept", "application/json");
        con.setRequestProperty("cache-control", "no-cache");
        con.setRequestProperty("content-type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Authorization", "Basic "+basicAuth);
        return con;
    }

    private String makeConnection(HttpURLConnection connection, String grantType, String scope) throws IOException {
        String jsonResponse = null;
        String urlParameters  = "grant_type="+grantType+"&scope="+scope;
        byte[] postData = urlParameters.getBytes( StandardCharsets.UTF_8 );
        connection.setRequestProperty("charset", "utf-8");
        connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
        connection.setUseCaches(false);
        connection.setDoOutput(true);
        
        try(DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
            wr.write( postData );
        }

        try(BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))){
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            jsonResponse = response.toString();
        }

        return jsonResponse;
         //connection.getResponseCode();
    }

    private void parseJsonResponse(String jsonResponse){
        Json j = Json.read(jsonResponse);
        int expiresInSec = Integer.parseInt(j.at("expires_in").toString());
        String accessTokenResponse = j.at("access_token").toString();

        //  fetchAccessToken.testConnection();
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cal.add(Calendar.SECOND, expiresInSec);
        this.expiresIn = cal.getTime();
        logger.info(String.format("accessToken expires in %s",this.expiresIn));
        accessToken = accessTokenResponse;
    }

    private boolean isAccessTokenValid(){
        if(accessToken == null) return false;
        Date currentDate = new Date();
        return this.expiresIn.compareTo(currentDate) > 0;
    }
    @Override
    public String getAccessToken() {
        if(this.isAccessTokenValid()) {
            logger.info(String.format(" accessToken valid %s",this.isAccessTokenValid()));
            return accessToken;
        }
        try {
            URL connectionURL = createConnectionURL(this.tenantURL);
            String basicAuthEncoding = getBasicAuthEncoding(this.clientID, this.clientSecret);
            HttpURLConnection connection = getConnection(connectionURL, basicAuthEncoding);
            String tokenResponse = makeConnection(connection, "client_credentials", this.scope);
            parseJsonResponse(tokenResponse);
            return accessToken;
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

}
