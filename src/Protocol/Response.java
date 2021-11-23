package Protocol;

import java.io.Serializable;
import java.util.HashMap;

public class Response implements Serializable {
    private Header header;
    private HashMap body;
    private HashMap params;

    public Response(){

        this.body = new HashMap();
        this.header = new Header();
    }

    public HashMap getBody() {
        return body;
    }

    public Header getHeader() {
        return header;
    }

}
