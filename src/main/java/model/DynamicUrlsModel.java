package model;

import com.alibaba.fastjson2.JSONArray;
import utils.CastUtils;

import java.util.List;

public class DynamicUrlsModel {
    private int id;
    private int basicPathNum;
    private List<String> pathToUrls;
    private List<String> unvisitedUrls;

    public DynamicUrlsModel(int id, int basic_path_num, JSONArray pathToUrls, JSONArray unvisitedUrls) {
        this.id = id;
        this.basicPathNum = basic_path_num;
        this.pathToUrls = CastUtils.toStringList(pathToUrls);
        this.unvisitedUrls = CastUtils.toStringList(unvisitedUrls);
    }

    public DynamicUrlsModel(int id, int basic_path_num, String pathToUrls, String unvisitedUrls) {
        this.id = id;
        this.basicPathNum = basic_path_num;
        this.pathToUrls = CastUtils.toStringList(CastUtils.toJsonArray(pathToUrls));
        this.unvisitedUrls =  CastUtils.toStringList(CastUtils.toJsonArray(unvisitedUrls));
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getBasicPathNum() {
        return basicPathNum;
    }

    public void setBasicPathNum(int basicPathNum) {
        this.basicPathNum = basicPathNum;
    }

    public List<String> getPathToUrls() {
        return pathToUrls;
    }

    public void setPathToUrls(List<String> pathToUrls) {
        this.pathToUrls = pathToUrls;
    }

    public List<String> getUnvisitedUrls() {
        return unvisitedUrls;
    }

    public void setUnvisitedUrls(List<String> unvisitedUrls) {
        this.unvisitedUrls = unvisitedUrls;
    }
}
