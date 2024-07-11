package model;

public class TableTabDataModel {
    private String msgHash;
    private String findUrl;
    private String findPath;
    private String findInfo;
    private String findApi;
    private String pathToUrl;
    private String unvisitedUrl;

    public TableTabDataModel(String msgHash, String findUrl, String findPath, String findInfo,
                             String findApi, String pathToUrl, String unvisitedUrl) {
        this.msgHash = msgHash;
        this.findUrl = findUrl;
        this.findPath = findPath;
        this.findInfo = findInfo;
        this.findApi = findApi;
        this.pathToUrl = pathToUrl;
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

    public String getPathToUrl() {
        return pathToUrl;
    }

    public String getUnvisitedUrl() {
        return unvisitedUrl;
    }
}
