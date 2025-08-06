package utils;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import sqlUtils.Constants;
import model.PathTreeModel;
import model.RecordPathDirsModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static utils.CastUtils.*;

public class PathTreeUtils {

    /**
     * 基于输入的PATH路径实现字典树的生成
     * @param uriPath
     * @return
     */
    public static JSONObject createRootTree(String uriPath) {
        List<String> filteredParts = getUrlPart(uriPath);
        // 初始化根节点
        JSONObject tree = new JSONObject();
        tree.put("ROOT", new JSONObject());

        // 用于追踪当前层级的JSONObject
        JSONObject currTreeNode = tree.getJSONObject("ROOT");
        for (String part : filteredParts) {
            //添加子节点
            if (!currTreeNode.containsKey(part)) {
                currTreeNode.put(part, new JSONObject());
            }

            //修改当前操作的节点为子节点
            currTreeNode = currTreeNode.getJSONObject(part);
        }

        return tree;
    }

    public static String formatUriPath(String uriPath) {
        return uriPath.replace("../", "").replace("./", "");
    }

    /**
     * 拆分输入的PATH路径为列表
     * @param uriPath
     * @return
     */
    public static List<String> getUrlPart(String uriPath) {
        // 去除URL首尾的斜杠并分割路径部分
        uriPath = formatUriPath(uriPath);
        String[] parts = uriPath.split("/");

        // 使用传统循环过滤掉空字符串
        List<String> filteredParts = new ArrayList<>();
        for (String part : parts) {
            if (isNotEmptyObj(part)) {
                filteredParts.add(part);
            }
        }
        return filteredParts;
    }

    /**
     * 深度合并两个json对象
     * @param baseTree
     * @param addTree
     * @return
     */
    public static JSONObject deepMergeJsonTree(JSONObject baseTree, JSONObject addTree) {
        if (isEmptyObj(baseTree))
            return addTree;
        if (isEmptyObj(addTree))
            return baseTree;

        for (Map.Entry<String, Object> entry : addTree.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (baseTree.containsKey(key)) {
                if (baseTree.get(key) instanceof JSONObject && value instanceof JSONObject) {
                    baseTree.put(key, deepMergeJsonTree(baseTree.getJSONObject(key), (JSONObject) value));
                } else if (baseTree.get(key) instanceof JSONArray && value instanceof JSONArray) {
                    // 这里简单合并数组，实际情况可能需要更复杂的逻辑处理
                    JSONArray array = new JSONArray();
                    array.addAll(baseTree.getJSONArray(key));
                    array.addAll((JSONArray) value);
                    baseTree.put(key, array);
                } else {
                    // 如果类型不同或非容器类型，选择第二个对象的值
                    baseTree.put(key, value);
                }
            } else {
                baseTree.put(key, value);
            }
        }
        return baseTree;
    }

    /**
     * 计算字符串中子字符串的数量
     * @param str
     * @param substr
     * @return
     */
    public static int counts(String str, String substr) {
        int index = 0;
        int count = 0;
        while ((index = str.indexOf(substr, index)) != -1) {
            count++;
            index += substr.length(); // 移动到子字符串下一个可能的起始位置
        }
        return count;
    }

    /**
     * 优化的带有查找数量限制的方案
     * @param subtree
     * @param targetKey
     * @param currentNodePath
     * @param maxFindPaths
     * @param foundPaths
     * @return
     */
    private static List<JSONArray> findNodePathsRecursive(JSONObject subtree, String targetKey, JSONArray currentNodePath, int maxFindPaths, AtomicInteger foundPaths) {
        List<JSONArray> findNodePathResult = new ArrayList<>();

        //判断是否有查找的必要,子链条字符串中都没有这个键,就可以直接忽略这个子树
        if(counts(subtree.toJSONString(), String.format("\"%s\"", targetKey)) < 1){
            return findNodePathResult;
        }

        // 检查是否已找到足够的路径
        if (foundPaths.get() >= maxFindPaths) {
            return findNodePathResult;
        }

        //开始对比当前键
        for (String currNode : subtree.keySet()) {
            JSONArray currNodePath = new JSONArray(currentNodePath);
            currNodePath.add(currNode);

            if (currNode.equalsIgnoreCase(targetKey)) {
                findNodePathResult.add(currNodePath);
                foundPaths.incrementAndGet();
                // 达到需要找到的节点路径数量,停止查找
                if (foundPaths.get() >= maxFindPaths) {
                    return findNodePathResult;
                }
            }

            //开始对比当前键的值（子树）
            Object valueAsNewTree = subtree.get(currNode);
            if (valueAsNewTree instanceof JSONObject) {
                // 传递已找到路径的数量和路径列表
                List<JSONArray> subNodePath = findNodePathsRecursive((JSONObject) valueAsNewTree, targetKey, currNodePath, maxFindPaths, foundPaths);
                findNodePathResult.addAll(subNodePath);
                // 达到需要找到的节点路径数量,停止查找
                if (foundPaths.get() >= maxFindPaths) {
                    return findNodePathResult;
                }
            }
        }
        return findNodePathResult;
    }

    /**
     * 输入根树节点和有顺序的键路径,获取键的值对象
     * @param jsonObject
     * @param pathKeys
     * @return
     */
    public static JSONObject findJsonValueByPaths(JSONObject jsonObject, JSONArray pathKeys) {
        JSONObject currentValue = jsonObject;
        for (Object key : pathKeys) {
            if (!(currentValue instanceof JSONObject)) {
                return null; // 如果当前值不是JSONObject，则路径不正确
            }
            currentValue = (JSONObject) currentValue.get(key);
            if (currentValue == null) {
                return null; // 如果在路径中的某个键未找到，则返回null
            }
        }
        return currentValue;
    }

    /**
     * 完整的子节点查找
     * @param rootTree
     * @param parts
     * @return
     */
    public static List<JSONArray> findNodePathInTree(JSONObject rootTree, List<String> parts) {
        List<JSONArray> endPaths = new ArrayList<>();

        //要搜索的位置,只搜索第一个,第二个作为补充即可,不要进行过多计算
        String targetKey = parts.get(0);
        int maxKeyCounts = counts(rootTree.toJSONString(), String.format("\"%s\"", targetKey));
        List<JSONArray> findNodePaths = findNodePathsRecursive(rootTree, targetKey, new JSONArray(), maxKeyCounts, new AtomicInteger(0));

        //找到一个节点信息
        if (findNodePaths.size() == 1 || parts.size() <= 1) {
            endPaths.addAll(findNodePaths);
        }

        //找到多个节点信息 并且还有其他关键字可以查找
        if (findNodePaths.size() > 1 && parts.size() > 1) {
            for (JSONArray nodePath : findNodePaths) {
                JSONObject subValueTree = findJsonValueByPaths(rootTree, nodePath);
//                System.out.println(String.format("根据 键路径 %s 在根树中找到值 %s", nodePath, subValueTree));
                if (counts(subValueTree.toJSONString(), String.format("\"%s\"", parts.get(1))) > 0) {
                    //找到了对应的子节点数据,就决定是它了
                    endPaths.add(nodePath);
                    //break; //考虑只查询一次, 节省递归次数
                }
            }
            //循环完毕都没有找到,还是重新用开始这几个吧,有总比没有好吧
            if (endPaths.size() < 1) endPaths.addAll(findNodePaths);
        }

        return endPaths;
    }

    /**
     * 将列表中的键拼接起来
     * @param endNodePaths
     * @return
     */
    public static JSONArray concatNodePaths(List<JSONArray> endNodePaths) {
        // 返回最终的列表
        JSONArray findPaths = new JSONArray();
        
        if (isNotEmptyObj(endNodePaths)){
            for (JSONArray endNodePath : endNodePaths) {
                // 确保每个元素都是字符串，因为String.join需要处理字符串数组
                List<String> stringPath = new ArrayList<>();
                for (Object obj : endNodePath) {
                    stringPath.add(obj.toString()); // 假设obj可以安全地转换为字符串
                }
                String joinedPath = String.join("/", stringPath);
                findPaths.add(joinedPath);
            }
        }

        return findPaths;
    }

    /**
     * 输入一个路径列表,自动合并|生成树
     * @param uriPathList
     * @return
     */
    public static JSONObject createRootTree(List<String> uriPathList) {
        //存储数据
        JSONObject baseTree = new JSONObject();
        if (isNotEmptyObj(uriPathList)) {
            //处理其他情况
            baseTree = createRootTree(uriPathList.get(0));
            for (int i = 1; i < uriPathList.size(); i++) {
                baseTree = deepMergeJsonTree(baseTree, createRootTree(uriPathList.get(i)));
            }
        }

        return baseTree;
    }

    /**
     * 过滤路径列表中的空和/
     * @param uriPathList
     * @return
     */
    public static List<String> filterBlankPath(List<String> uriPathList) {
        List list = new ArrayList<String>();
        for (String path: uriPathList){
            if (isNotEmptyObj(path) &&  !"/".equals(path.trim()))
                list.add(path);
        }
        return list;
    }

    /**
     * 生成路径树  输入格式 {host:[path list]}
     */
    public static PathTreeModel genPathsTree(RecordPathDirsModel recordPathModel) {
        PathTreeModel pathTreeModel = null;

        // 3、为每个域名计算根数
        String[] reqPathDirsToPaths = recordPathModel.getReqPathDirs().split(Constants.SPLIT_SYMBOL);
        if (reqPathDirsToPaths.length > 0) {
            List<String> filterPaths = filterBlankPath(Arrays.asList(reqPathDirsToPaths));
            JSONObject newPathTree = createRootTree(filterPaths);
            if (isNotEmptyObj(newPathTree)){
                pathTreeModel = new PathTreeModel(
                        recordPathModel.getRootUrl(),
                        reqPathDirsToPaths.length,
                        newPathTree
                );
            }
        }

        return pathTreeModel;
    }


    public static JSONArray findNodePathInTree(JSONObject tree, String sub_url) {
        JSONArray findPaths = new JSONArray();

        List<String> sub_parts = getUrlPart(sub_url);
        if (isNotEmptyObj(sub_parts)) {
            //从树中寻找可能的节点路径
            List<JSONArray> endNodePaths = findNodePathInTree(tree, sub_parts);
            if (isNotEmptyObj(endNodePaths))
                findPaths = concatNodePaths(endNodePaths);
        }
        return findPaths;
    }

    /**
     * 基于Json树生成所有Path
     */
    private static List<String> covertTreeToPaths(JSONObject json, String path) {
        List<String> paths = new ArrayList<>();
        for (Map.Entry<String, Object> entry : json.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // 构建新的路径
            String newPath = path.isEmpty() ? key : path + "/" + key;
            paths.add(newPath);

            if (value instanceof JSONObject) {
                // 如果值是JSONObject，递归调用
                // 注意：这里的collectJsonPaths调用不需要额外的List参数
                paths.addAll(covertTreeToPaths((JSONObject) value, newPath));
            }
        }
        return paths;
    }

    public static List<String> covertTreeToPaths(JSONObject tree) {
        return covertTreeToPaths(tree, "");
    }


    public static void main(String[] args) {
        String url = "/biz-gateway/walletParam/paramTypeGroup/findListByGroupName";
        JSONObject tree = createRootTree(url);
        System.out.println(tree.toJSONString());

        String url2 = "/biz-gateway/walletSystem/sysLogin/randomImage/1715413128";
        JSONObject tree2 = createRootTree(url2);
        System.out.println(tree2.toJSONString());

        tree = deepMergeJsonTree(tree, tree2);
        System.out.println(tree.toJSONString());

        String url3 = "/biz-gateway/walletSystem/sysLogin/randomImage/walletParam";
        tree = deepMergeJsonTree(tree, createRootTree(url3));
        System.out.println(tree.toJSONString());

        String sub_url = "../walletParam/paramTypeGroup/findListByGroupName";
        JSONArray findNode = findNodePathInTree(tree, sub_url);
        System.out.println(findNode.toJSONString());

        List<String> paths = covertTreeToPaths(tree);
        System.out.println(paths);
    }
}