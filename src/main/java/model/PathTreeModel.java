package model;

import com.alibaba.fastjson2.JSONObject;
import utils.CastUtils;

public class PathTreeModel {
    private String reqProto;
    private String reqHostPort;
    private Integer basicPathNum;
    private JSONObject pathTree;

    public PathTreeModel(String reqProto, String reqHostPort, Integer basicPathNum, JSONObject pathTree) {
        this.reqProto = reqProto;
        this.reqHostPort = reqHostPort;
        this.basicPathNum = basicPathNum;
        this.pathTree = pathTree;
    }

    public PathTreeModel(String reqProto, String reqHostPort, int basicPathNum, String pathTree) {
        this.reqProto = reqProto;
        this.reqHostPort = reqHostPort;
        this.basicPathNum = basicPathNum;
        this.pathTree = CastUtils.toJsonObject(pathTree);
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
