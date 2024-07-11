package model;

import com.alibaba.fastjson2.JSONArray;
import utils.CastUtils;

import java.util.List;

public class UnVisitedUrlsModel {
    private int id;
    private List<String> unvisitedUrls;

    public UnVisitedUrlsModel(int id, JSONArray unvisitedUrls) {
        this.id = id;
        this.unvisitedUrls = CastUtils.toStringList(unvisitedUrls);
    }

    public UnVisitedUrlsModel(int id, String unvisitedUrls) {
        this.id = id;
        this.unvisitedUrls =  CastUtils.toStringList(CastUtils.toJsonArray(unvisitedUrls));
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<String> getUnvisitedUrls() {
        return unvisitedUrls;
    }

    public void setUnvisitedUrls(List<String> unvisitedUrls) {
        this.unvisitedUrls = unvisitedUrls;
    }
}
