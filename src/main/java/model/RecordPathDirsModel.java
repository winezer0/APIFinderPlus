package model;

public class RecordPathDirsModel {
    private String rootUrl;
    private String reqPathDirs;

    // 构造函数
    public RecordPathDirsModel(String rootUrl, String reqPathDirs) {
        this.rootUrl = rootUrl;
        this.reqPathDirs = reqPathDirs;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public String getReqPathDirs() {
        return reqPathDirs;
    }
}
