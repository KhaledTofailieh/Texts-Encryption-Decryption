package Protocol;

import java.io.Serializable;
import java.util.HashMap;

public class Header implements Serializable {
    private Methods method;
    private int status;
    private HashMap params;

    Header(){
        this.params = new HashMap();
    }
    Header(Methods method){
        this.method= method;
        this.params = new HashMap();
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public Methods getMethod() {
        return method;
    }

    public void setMethod(Methods method) {
        this.method = method;
    }

    public HashMap getParams() {
        return params;
    }
}
