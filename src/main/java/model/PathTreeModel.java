package model;

import com.alibaba.fastjson2.JSONObject;
import utils.CastUtils;

public class PathTreeModel {
    private String rootUrl;
    private Integer basicPathNum;
    private JSONObject pathTree;

    public PathTreeModel(String rootUrl, Integer basicPathNum, JSONObject pathTree) {
        this.rootUrl = rootUrl;
        this.basicPathNum = basicPathNum;
        this.pathTree = pathTree;
    }

    public PathTreeModel(String rootUrl, int basicPathNum, String pathTree) {
        this.rootUrl = rootUrl;
        this.basicPathNum = basicPathNum;
        this.pathTree = CastUtils.toJsonObject(pathTree);
    }



    public Integer getBasicPathNum() {
        return basicPathNum;
    }

    public JSONObject getPathTree() {
        return pathTree;
    }

    public String getRootUrl() {
        return rootUrl;
    }
}
