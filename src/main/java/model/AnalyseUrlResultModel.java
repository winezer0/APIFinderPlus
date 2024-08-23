package model;

import com.alibaba.fastjson2.JSONArray;
import utils.CastUtils;

import java.util.List;

public class AnalyseUrlResultModel {
    private String reqUrl;
    private JSONArray infoArray;
    private List<String> urlList;
    private List<String> pathList;
    private List<String> apiList;
    private List<String> unvisitedUrl; //TODO 后续需要删除 unvisitedUrl ，在集成面板中显示即可
    private Boolean hasImportant;

    //新增一个URL类型的
    public AnalyseUrlResultModel(String reqUrl, JSONArray infoArray, List<String> urlList, List<String> pathList, List<String> apiList, Boolean hasImportant) {
        this.reqUrl = reqUrl;
        this.infoArray = infoArray;
        this.urlList = urlList;
        this.pathList = pathList;
        this.apiList = apiList;
        this.unvisitedUrl = CastUtils.listAddList(this.urlList, this.apiList); //TODO 待删除
        this.hasImportant = hasImportant;
    }

    public AnalyseUrlResultModel(String reqUrl, String infoJsonArrayStr, String urlListStr, String pathListStr, String apiListStr, Boolean hasImportant) {
        this.reqUrl = reqUrl;
        this.infoArray = CastUtils.toJsonArray(infoJsonArrayStr);
        this.urlList = CastUtils.toStringList(urlListStr);
        this.pathList = CastUtils.toStringList(pathListStr);
        this.apiList = CastUtils.toStringList(apiListStr);
        this.unvisitedUrl = CastUtils.listAddList(this.urlList, this.apiList); //TODO 待删除
        this.hasImportant = hasImportant;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public JSONArray getInfoArray() {
        return infoArray;
    }

    public List<String> getUrlList() {
        return urlList;
    }

    public List<String> getPathList() {
        return pathList;
    }

    public List<String> getApiList() {
        return apiList;
    }

    public List<String> getUnvisitedUrl() {
        return unvisitedUrl;
    }

    public Boolean getHasImportant() {
        return hasImportant;
    }
}
