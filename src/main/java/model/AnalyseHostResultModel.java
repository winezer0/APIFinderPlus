package model;

import com.alibaba.fastjson2.JSONArray;
import utils.CastUtils;

import java.util.List;

/**
 * 用来存储基于主机的结果的模型
 */
public class AnalyseHostResultModel {
    private String rootUrl;
    private JSONArray infoArray;
    private List<String> urlList;
    private List<String> pathList;
    private List<String> apiList;
    private Boolean hasImportant;
    private List<String> unvisitedUrlList;


//    // 全参数构造函数
//    public AnalyseHostResultModel(String rootUrl, JSONArray infoArray, List<String> urlList, List<String> pathList, List<String> apiList, Boolean hasImportant) {
//        this.rootUrl = rootUrl;
//        this.infoArray = infoArray;
//        this.urlList = urlList;
//        this.pathList = pathList;
//        this.apiList = apiList;
//        this.hasImportant = hasImportant;
//    }

    // 中转构造函数
    public AnalyseHostResultModel(AnalyseUrlResultModel analyseUrlResultModel) {
        this.rootUrl = new HttpUrlInfo(analyseUrlResultModel.getReqUrl()).getRootUrl();
        this.infoArray = analyseUrlResultModel.getInfoArray();
        this.urlList = analyseUrlResultModel.getUrlList();
        this.pathList = analyseUrlResultModel.getPathList();
        this.apiList = analyseUrlResultModel.getApiList();
        this.hasImportant = analyseUrlResultModel.getHasImportant();
        this.unvisitedUrlList = CastUtils.listAddList(this.urlList, this.apiList);
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public void setRootUrl(String rootUrl) {
        this.rootUrl = rootUrl;
    }

    public JSONArray getInfoArray() {
        return infoArray;
    }

    public void setInfoArray(JSONArray infoArray) {
        this.infoArray = infoArray;
    }

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

    public List<String> getApiList() {
        return apiList;
    }

    public void setApiList(List<String> apiList) {
        this.apiList = apiList;
    }

    public Boolean getHasImportant() {
        return hasImportant;
    }

    public void setHasImportant(Boolean hasImportant) {
        this.hasImportant = hasImportant;
    }

    public List<String> getUnvisitedUrlList() {
        return unvisitedUrlList;
    }

    public void setUnvisitedUrlList(List<String> unvisitedUrlList) {
        this.unvisitedUrlList = unvisitedUrlList;
    }
}