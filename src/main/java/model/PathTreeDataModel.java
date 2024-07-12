package model;

import com.alibaba.fastjson2.JSONObject;

public class PathTreeDataModel {
    private String reqProto;
    private String reqHostPort;
    private Integer basicPathNum;
    private JSONObject pathTree;

    public PathTreeDataModel(String reqProto, String reqHostPort, Integer basicPathNum, JSONObject pathTree) {
        this.reqProto = reqProto;
        this.reqHostPort = reqHostPort;
        this.basicPathNum = basicPathNum;
        this.pathTree = pathTree;
    }

    public String getReqProto() {
        return reqProto;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public Integer getBasicPathNum() {
        return basicPathNum;
    }

    public JSONObject getPathTree() {
        return pathTree;
    }
}
