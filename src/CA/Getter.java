package CA;

import Protocol.Query;
import Protocol.Request;
import Protocol.Response;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HashMap;

public class Getter {
    private Request request;
    private KeyPair CAKeys;
    private HashMap gift_certificates;
    private String CAName;
    Getter(Request req, KeyPair caKeys, HashMap gift_certificates,String CAName){
        this.request = req;
        this.CAKeys = caKeys;
        this.gift_certificates = gift_certificates;
        this.CAName = CAName;
    }
   public Response getResponse() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
     Response response= new Response();
      switch((Query)request.getParams().get("query")){

          case Certificate:{
              PublicKey server_key = (PublicKey)request.getBody().get("public");
              String server_name = (String)request.getBody().get("serverName");
              Certificate certificate;
              certificate = (Certificate) this.gift_certificates.get(server_key.getEncoded());
              if(certificate == null){
                  certificate = new Certificate(CAKeys,server_key,server_name,this.CAName);
              }
              response.getHeader().setStatus(200);
              response.getBody().put("certificate",certificate);
             break;
          }
          case public_key:{
              response.getHeader().setStatus(200);
              CA ca = new CA(this.CAKeys.getPublic(), this.CAName);
              response.getBody().put("ca",ca);
              break;
          }
          default:{
              response.getHeader().setStatus(400);
              response.getBody().put("msg","Not Defined Operator!!");
          }
      }
      return response;
    }

}
