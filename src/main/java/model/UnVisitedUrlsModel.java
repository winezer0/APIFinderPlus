package model;

import utils.CastUtils;

import java.util.List;

public class UnVisitedUrlsModel {
    private int id;
    private String reqUrl;
    private String msgHash;
    private List<String> unvisitedUrls;

    public UnVisitedUrlsModel(int id, String msgHash, String reqUrl, String unvisitedUrl) {
        this.id = id;
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.unvisitedUrls =  CastUtils.toStringList(CastUtils.toJsonArray(unvisitedUrl));
    }

    public int getId() {
        return id;
    }

    public String getMsgHash() {
        return msgHash;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public List<String> getUnvisitedUrls() {
        return unvisitedUrls;
    }

    public void setUnvisitedUrls(List<String> unvisitedUrls) {
        this.unvisitedUrls = unvisitedUrls;
    }
}
