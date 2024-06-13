package model;

import com.alibaba.fastjson2.JSONArray;

import java.util.ArrayList;
import java.util.List;

//存储响应提取信息的模型
public class AnalyseInfo {
    List<String> urlList = new ArrayList<>();
    List<String> pathList = new ArrayList<>();
    JSONArray infoArray = new JSONArray();

    public List<String> getUrlList() {
        return urlList;
    }

    public void setUrlList(List<String> urlList) {
        this.urlList = urlList;
    }

    public List<String> getPathList() {
        return pathList;
    }

    public void setPathList(List<String> pathList) {
        this.pathList = pathList;
    }

    public JSONArray getInfoArray() {
        return infoArray;
    }

    public void setInfoArray(JSONArray infoArray) {
        this.infoArray = infoArray;
    }
}
