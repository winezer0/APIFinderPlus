package model;

import com.alibaba.fastjson2.JSONArray;
import utils.PathTreeUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class FindPathModel {
    private int id;
    private String rootUrl;
    private JSONArray findPath;


    public FindPathModel(int id, String rootUrl, String findPath) {
        this.id = id;
        this.rootUrl = rootUrl;
        this.findPath = JSONArray.parse(findPath);
    }

    public int getId() {
        return id;
    }


    public String getRootUrl() {
        return rootUrl;
    }


    public JSONArray getFindPath() {
        return findPath;
    }


    /**
     * 从路径模型中获取单层路径
     * @param findPathModelList
     * @return
     */
    public static Set<String> getSingleLayerPathSet(List<FindPathModel> findPathModelList) {
        Set<String> pathSet = new LinkedHashSet<>();
        //查询msgHash列表对应的所有数据find path 数据
        for (FindPathModel findPathModel: findPathModelList){
            //逐个提取PATH 并 加入 pathSet
            JSONArray findPaths = findPathModel.getFindPath();
            if (!findPaths.isEmpty()){
                // 提取 path中的单层路径
                for (Object uriPath : findPaths){
                    List<String> uriPart = PathTreeUtils.getUrlPart((String) uriPath);
                    if (uriPart.size() == 1){
                        pathSet.add(PathTreeUtils.formatUriPath((String) uriPath));
                    }
                }
            }
        }
        return pathSet;
    }
}
