package model;

public class BasicUrlTableTabDataModel {
    private String msgHash;
    private String findUrl;
    private String findPath;
    private String findInfo;
    private String findApi;

    public BasicUrlTableTabDataModel(String msgHash, String findUrl, String findPath, String findInfo,
                                     String findApi) {
        this.msgHash = msgHash;
        this.findUrl = findUrl;
        this.findPath = findPath;
        this.findInfo = findInfo;
        this.findApi = findApi;
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
}
