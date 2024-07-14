package model;

import static utils.CastUtils.calcCRC32;

public  class AccessedUrlInfo {
    public String reqUrl;
    public String urlHash;
    public String reqHostPort;
    public int respStatusCode;

    public AccessedUrlInfo(String reqUrl, String reqHostPort, int respStatusCode) {
        this.reqUrl = reqUrl;
        this.reqHostPort = reqHostPort;
        this.respStatusCode = respStatusCode;
        this.urlHash = calcCRC32(reqUrl);
    }

    public String getUrlHash() {
        return urlHash;
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