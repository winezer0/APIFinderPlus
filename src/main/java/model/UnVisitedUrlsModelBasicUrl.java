package model;

import utils.CastUtils;

import java.util.List;

//TODO 待删除基于URL的未访问URL记录
public class UnVisitedUrlsModelBasicUrl {
    private int id;
    private String reqUrl;
    private String msgHash;
    private List<String> unvisitedUrls;

    public UnVisitedUrlsModelBasicUrl(int id, String msgHash, String reqUrl, String unvisitedUrl) {
        this.id = id;
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.unvisitedUrls =  CastUtils.toStringList(unvisitedUrl);
    }

    public UnVisitedUrlsModelBasicUrl(int id, String msgHash, String reqUrl, List<String> unvisitedUrl) {
        this.id = id;
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.unvisitedUrls =  unvisitedUrl;
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
