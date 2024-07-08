package model;

public class TableTabDataModel {
    private String msgHash;
    private String findUrl;
    private String findPath;
    private String findInfo;
    private String findApi;
    private String smartApi;
    private String unvisitedUrl;

    public TableTabDataModel(String msgHash, String findUrl, String findPath, String findInfo,
                             String findApi, String smartApi, String unvisitedUrl) {
        this.msgHash = msgHash;
        this.findUrl = findUrl;
        this.findPath = findPath;
        this.findInfo = findInfo;
        this.findApi = findApi;
        this.smartApi = smartApi;
        this.unvisitedUrl = unvisitedUrl;
    }

    public String getMsgHash() {
        return msgHash;
    }

    public String getFindUrl() {
        return findUrl;
    }

    public String getFindPath() {
        return findPath;
    }

    public String getFindInfo() {
        return findInfo;
    }

    public String getFindApi() {
        return findApi;
    }

    public String getSmartApi() {
        return smartApi;
    }

    public String getUnvisitedUrl() {
        return unvisitedUrl;
    }
}
