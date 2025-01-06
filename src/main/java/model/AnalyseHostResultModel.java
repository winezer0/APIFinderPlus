package model;

import com.alibaba.fastjson2.JSONArray;
import utils.CastUtils;

import java.util.HashMap;
import java.util.List;

/**
 * 用来存储基于主机的结果的模型
 */
public class AnalyseHostResultModel {
    private String rootUrl;
    private HashMap<String, JSONArray> urlInfoArrayMap;
    private List<String> urlList;
    private List<String> pathList;
    private List<String> apiList;
    private Boolean hasImportant;

    // 中转构造函数
    public AnalyseHostResultModel(AnalyseUrlResultModel analyseUrlResultModel) {
        this.rootUrl = new HttpUrlInfo(analyseUrlResultModel.getReqUrl()).getRootUrlUsual();
        this.urlInfoArrayMap = analyseUrlResultModel.getUrlInfoArrayMap();
        this.urlList = analyseUrlResultModel.getUrlList();
        this.pathList = analyseUrlResultModel.getPathList();
        this.apiList = analyseUrlResultModel.getApiList();
        this.hasImportant = analyseUrlResultModel.getHasImportant();
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public HashMap<String, JSONArray> getUrlInfoArrayMap() {
        return urlInfoArrayMap;
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

    public Boolean getHasImportant() {
        return hasImportant;
    }

    public List<String> getUnvisitedUrlList() {
        return CastUtils.listAddList(this.urlList, this.apiList);
    }

    public List<String> getUnvisitedUrlList(boolean addApiList) {
        if (addApiList)
            return CastUtils.listAddList(this.urlList, this.apiList);
        else
            return this.urlList;
    }
}