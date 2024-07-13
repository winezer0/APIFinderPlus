package model;

public  class AccessedUrlInfo {
    public String reqUrl;
    public String reqHostPort;
    public int respStatusCode;

    public AccessedUrlInfo(String reqUrl, String reqHostPort, int respStatusCode) {
        this.reqUrl = reqUrl;
        this.reqHostPort = reqHostPort;
        this.respStatusCode = respStatusCode;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public int getRespStatusCode() {
        return respStatusCode;
    }
}