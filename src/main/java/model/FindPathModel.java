package model;

public class FindPathModel {
    private int id;
    private String reqUrl;
    private String reqHostPort;
    private String findPath;


    public FindPathModel(int id, String reqUrl, String reqHostPort, String findPath) {
        this.id = id;
        this.reqUrl = reqUrl;
        this.reqHostPort = reqHostPort;
        this.findPath = findPath;
    }

    public int getId() {
        return id;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public String getFindPath() {
        return findPath;
    }
}
