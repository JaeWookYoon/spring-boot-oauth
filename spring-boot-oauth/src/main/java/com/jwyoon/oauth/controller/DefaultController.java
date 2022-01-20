package com.jwyoon.oauth.controller;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import com.jwyoon.oauth.model.UserList;
import com.jwyoon.oauth.repository.UserListRepository;
import com.jwyoon.oauth.util.ContextPathResolver;

@RestController
public class DefaultController {

    private ContextPathResolver ctxPath = new ContextPathResolver();
    @Autowired
    private UserListRepository userListRepository;
    
    @GetMapping("/")
    public String home1() {
        return null;
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/home")
    public String home(HttpServletRequest request) throws ClientProtocolException, IOException {
        HttpSession session = request.getSession(false);


        return null;
    }

    @GetMapping("/admin")
    public String admin() {
        return null;
    }

    @GetMapping("/user")
    public String user(HttpServletRequest req) {
        HttpSession session = req.getSession(false);

        return null;
    }

    @GetMapping("/about")
    public String about() {
        return null;
    }

    @GetMapping("/login")
    public String login() {
        return null;
    }

    @GetMapping("/403")
    public String error403() {
        return "/error/403";
    }

    @RequestMapping(value = "/getmessage", method = RequestMethod.GET, produces = "application/json")
    public @ResponseBody
    String getMessage() {
        // response body 濡� Message 媛앹껜瑜�? JSON �삎�떇�쑝濡� 蹂�?궡以�?.
        return "Congratulations! You have accessed a Basic Auth protected resource.";
    }

    @RequestMapping(value = "/request", method = RequestMethod.POST)
    @ResponseBody
    public String decryptRequest(String enmsg) throws IOException, ParseException {
        System.out.println(enmsg);
        //�븞�뱶濡쒖?���뱶�뿉�꽌 �삩 洹몃��?�� 硫붿�?吏�
        String foo = enmsg.replace("\n","").trim();
        System.out.println(foo);
        JSONParser parser = new JSONParser();
        //蹂듯?���솕�썑 JSON�쑝濡� �뜕�젘�떎.
        System.out.println(foo.toString());
        String finalFoo = jsonToToken((JSONObject) parser.parse(foo));
        return finalFoo;
    }

    public String jsonToToken(JSONObject object) throws ClientProtocolException, IOException {

        String username = (String) object.get("username");
        String password = (String) object.get("password");
        String client_id = (String) object.get("client_id");
        JSONObject json = new JSONObject();
        
        HttpPost post = new HttpPost("http://localhost:8080/oauth/token");
        Map<String,Object> form = new HashMap<String,Object>();

        
        form.put("grant_type", "password");
        form.put("username", username);
        form.put("password", password);
        form.put("client_id", client_id);
        //UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, Consts.UTF_8);
        UserList user = userListRepository.findUserById(username);
        
        String auth = username + ":" + user.getIdx();// userlist Idx ?? oauth_client_details client_secret?�� ?��?��매핑?��???��.
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
        String authHeader = "Basic " + new String(encodedAuth);
        System.out.println(auth + " , Basic "+new String(encodedAuth));
        post.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
        JSONParser parser = new JSONParser();
        String result = null;
        try {
			  WebClient web = WebClient.create();
			  result = web.post().
			  uri("http://localhost:8080/oauth/token")
			  .header(HttpHeaders.AUTHORIZATION, authHeader)
			  //.header("Content-Type","application/x-www-form-urlencoded; charset=utf-8")
			  .contentType(MediaType.APPLICATION_FORM_URLENCODED)
			  .acceptCharset(Charset.forName("UTF-8"))
			  .bodyValue("grant_type=password&username="+username+"&password="+password)			  
			  .retrieve()
			  .bodyToMono(JSONObject.class)
			  .block().toJSONString();
			 
			  JSONObject resultJ = (JSONObject)parser.parse(result);
			  System.out.println(resultJ.get("access_token"));
			 
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Token has been generated");

        return result;
    }

    //code  諛쒓?�� 諛� �넗�겙 諛쒓?��
    /*@RequestMapping("/callback")
    @ResponseBody
    public JSONObject getCodeAndReTreatToken(HttpServletRequest request) throws ClientProtocolException, IOException {
        System.out.println("�옒�뱾�떎吏꾩�?"+request.getQueryString());
        HttpSession session = request.getSession(false);
        JSONObject json = new JSONObject();
        if (request.getParameter("code") != null) {

            String code = request.getParameter("code");
            System.out.println(request.toString());
            session.setAttribute("authorizationCode", code);
            String username = (String) session.getAttribute("username");
            String password = (String) session.getAttribute("password");
            System.out.println("code = " + code);

            HttpClient client = new DefaultHttpClient();
            HttpPost post = new HttpPost(ctxPath.contextPathResolve(request) + "/oauth/token");

            List<NameValuePair> form = new ArrayList<>();

            form.add(new BasicNameValuePair("grant_type", "authorization_code"));
            form.add(new BasicNameValuePair("code", code));
            form.add(new BasicNameValuePair("redirect_uri", "/callback"));
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, Consts.UTF_8);

            String auth = username + ":" + password;
            byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
            String authHeader = "Basic " + new String(encodedAuth);
            post.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
            post.setHeader("Content-Type", "application/x-www-form-urlencoded");
            post.setEntity(entity);
            HttpResponse response = client.execute(post);
            JSONParser parser = new JSONParser();
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                String str = "";
                StringBuffer strBuf = new StringBuffer();
                while ((str = br.readLine()) != null) {
                    strBuf.append(str);
                }
                System.out.println("strBuf = " + strBuf.toString());
                json = (JSONObject) parser.parse(strBuf.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println(json.toString());
        return json;
    }*/
}
