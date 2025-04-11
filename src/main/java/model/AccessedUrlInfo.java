package model;

import static utils.RespHashUtils.calcCRC32;

public  class AccessedUrlInfo {
    public String rootUrl;
    public String reqUrl;
    public String urlHash;
    public int respStatusCode;

    public AccessedUrlInfo(String reqUrl, String rootUrl, int respStatusCode) {
        this.reqUrl = reqUrl;
        this.rootUrl = rootUrl;
        this.respStatusCode = respStatusCode;
        this.urlHash = calcCRC32(reqUrl);
    }

    public String getUrlHash() {
        return urlHash;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public int getRespStatusCode() {
        return respStatusCode;
    }


}