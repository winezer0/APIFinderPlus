package model;

public class RecordPathDirsModel {
    private String reqProto;
    private String reqHostPort;
    private String reqPathDirs;

    // 构造函数
    public RecordPathDirsModel(String reqProto, String reqHostPort, String reqPathDirs) {
        this.reqProto = reqProto;
        this.reqHostPort = reqHostPort;
        this.reqPathDirs = reqPathDirs;
    }

    public String getReqProto() {
        return reqProto;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public String getReqPathDirs() {
        return reqPathDirs;
    }
}
