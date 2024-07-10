package model;

import com.alibaba.fastjson2.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AnalyseResult {
    private List<JSONObject> infoList;
    private List<String> urlList;
    private List<String> pathList;
    private List<String> apiList;
    private List<String> unvisitedUrl;

    public AnalyseResult(List<JSONObject> infoList, List<String> urlList, List<String> pathList, List<String> apiList) {
        this.infoList = infoList;
        this.urlList = urlList;
        this.pathList = pathList;
        this.apiList = apiList;
        this.unvisitedUrl = mergeAndDedupLists(urlList, apiList);
    }

    public List<JSONObject> getInfoList() {
        return infoList;
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

    /**
     * 合并并去重两个List
     * @param firstList
     * @param secondList
     * @return
     */
    private  List<String> mergeAndDedupLists(List<String> firstList, List<String> secondList) {
        // 使用 LinkedHashSet 来存储合并后的列表，这将自动去除重复元素并保持插入顺序
        Set<String> set = new HashSet<>(firstList);
        set.addAll(secondList);

        // 将 Set 转换回 List 并返回
        return new ArrayList<>(set);
    }

    public void setUnvisitedUrl(List<String> unvisitedUrl) {
        this.unvisitedUrl = unvisitedUrl;
    }
}
