package model;

import utils.CastUtils;

import java.util.List;

public class UnVisitedUrlsModel {
    private int id;
    private String rootUrl;
    private List<String> unvisitedUrls;

    public UnVisitedUrlsModel(int id, String rootUrl, String unvisitedUrl) {
        this.id = id;
        this.rootUrl = rootUrl;
        this.unvisitedUrls =  CastUtils.toStringList(unvisitedUrl);
    }

    public int getId() {
        return id;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public List<String> getUnvisitedUrls() {
        return unvisitedUrls;
    }

    public void setUnvisitedUrls(List<String> unvisitedUrls) {
        this.unvisitedUrls = unvisitedUrls;
    }
}
