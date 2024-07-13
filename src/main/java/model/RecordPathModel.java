package model;

public class RecordPathModel {
    private String reqProto;
    private String reqHostPort;
    private String reqPathDir;
    private int respStatusCode;

    public RecordPathModel(String reqProto, String reqHostPort, String reqPathDir, int respStatusCode) {
        this.reqProto = reqProto;
        this.reqHostPort = reqHostPort;
        this.reqPathDir = reqPathDir;
        this.respStatusCode = respStatusCode;
    }

    public String getReqProto() {
        return reqProto;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public String getReqPathDir() {
        return reqPathDir;
    }

    public int getRespStatusCode() {
        return respStatusCode;
    }
}
