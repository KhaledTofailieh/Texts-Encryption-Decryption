package Protocol;

import java.io.Serializable;
import java.util.HashMap;

public class Request implements Serializable {
    private Header header;
    private HashMap params;
    private HashMap body;

    public Request(Methods method){
        this.header = new Header(method);
        this.params = new HashMap();
        this.body = new HashMap();
    }
    public Request(Methods method,Query query){
        this.header = new Header(method);
        this.params = new HashMap();
        params.put("query",query);
        this.body = new HashMap();
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public HashMap getBody() {
        return body;
    }

    public HashMap getParams() {
        return params;
    }
}
