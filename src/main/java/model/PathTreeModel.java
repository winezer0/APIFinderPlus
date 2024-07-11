package model;

import com.alibaba.fastjson2.JSONObject;

public class PathTreeModel {
    private int basicPathNum;
    private JSONObject pathTree;

    public PathTreeModel(int basicPathNum, String pathTree) {
        this.basicPathNum = basicPathNum;
        this.pathTree = JSONObject.parse(pathTree);
    }

    public PathTreeModel(int basicPathNum,JSONObject pathTree) {
        this.basicPathNum = basicPathNum;
        this.pathTree = pathTree;
    }


    public int getBasicPathNum() {
        return basicPathNum;
    }

    public JSONObject getPathTree() {
        return pathTree;
    }

}
