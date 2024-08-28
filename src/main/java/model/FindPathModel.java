package model;

import com.alibaba.fastjson2.JSONArray;

public class FindPathModel {
    private int id;
    private String rootUrl;
    private JSONArray findPath;


    public FindPathModel(int id, String rootUrl, String findPath) {
        this.id = id;
        this.rootUrl = rootUrl;
        this.findPath = JSONArray.parse(findPath);
    }

    public int getId() {
        return id;
    }


    public String getRootUrl() {
        return rootUrl;
    }

    public JSONArray getFindPath() {
        return findPath;
    }
}
