package model;

import com.alibaba.fastjson2.JSONArray;

public class FindPathModel {
    private int id;
    private String reqUrl;
    private String rootUrl;
    private JSONArray findPath;


    public FindPathModel(int id, String reqUrl, String rootUrl, String findPath) {
        this.id = id;
        this.reqUrl = reqUrl;
        this.rootUrl = rootUrl;
        this.findPath = JSONArray.parse(findPath);
    }

    public int getId() {
        return id;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public JSONArray getFindPath() {
        return findPath;
    }
}
