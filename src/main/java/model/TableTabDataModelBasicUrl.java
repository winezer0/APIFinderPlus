package model;

public class TableTabDataModelBasicUrl {
    private String msgHash;
    private String findUrl;
    private String findPath;
    private String findInfo;
    private String findApi;
    private String pathToUrl;
    private String unvisitedUrl;

    public TableTabDataModelBasicUrl(String msgHash, String findUrl, String findPath, String findInfo,
                                     String findApi, String pathToUrl, String unvisitedUrl) {
        this.msgHash = msgHash;
        this.findUrl = findUrl;
        this.findPath = findPath;
        this.findInfo = findInfo;
        this.findApi = findApi;
        this.pathToUrl = pathToUrl;  //TODO 后续需要删除
        this.unvisitedUrl = unvisitedUrl; //TODO 后续需要删除
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
