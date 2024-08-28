package model;

public class TableTabDataModelBasicHost {
    private String rootUrl;

    private String findInfo;
    private String findUrl;
    private String findPath;
    private String findApi;

    private String pathToUrl;
    private String unvisitedUrl;


    public TableTabDataModelBasicHost(String rootUrl, String findInfo, String findUrl, String findPath,
                                      String findApi, String pathToUrl, String unvisitedUrl) {
        this.rootUrl = rootUrl;
        this.findUrl = findUrl;
        this.findPath = findPath;
        this.findInfo = findInfo;
        this.findApi = findApi;
        this.pathToUrl = pathToUrl;
        this.unvisitedUrl = unvisitedUrl;
    }

    public String getRootUrl() {
        return rootUrl;
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
