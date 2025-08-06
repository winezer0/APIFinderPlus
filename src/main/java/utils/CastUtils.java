package utils;

import burp.AnalyseInfo;
import burp.BurpExtender;
import com.alibaba.fastjson2.*;
import sqlUtils.Constants;
import model.HttpUrlInfo;
import utilbox.HelperPlus;

import java.util.*;

public class CastUtils {
    /**
     * 防止操作的list是null值
     */
    private static List<String> fixedNullList(List<String> list) {
        if (list == null)  list = new ArrayList<>();
        return list;
    }

    /**
     * 将任意类型的List转为Json字符串
     */
    public static String toJsonString(List<?> list){
        return com.alibaba.fastjson2.JSON.toJSONString(list);
    }

    /**
     * 将任意类型转为Json字符串
     */
    public static String toJsonString(Object object){
        return com.alibaba.fastjson2.JSON.toJSONString(object);
    }

    /**
     * List<String> list 元素去重
     */
    public static List<String> deduplicateStringList(List<String> list) {
        if (isEmptyObj(list)) return new ArrayList<>();

        return new ArrayList<>(new HashSet<>(list));
    }

    /**
     * 去除JSONArray中的重复项。
     *
     * @param jsonArray 需要去重的原始列表。
     * @return 去重后的列表。
     */
    public static JSONArray deduplicateJsonArray(JSONArray jsonArray) {
        if (jsonArray == null || jsonArray.size() == 0)
            return new JSONArray();

        // 使用LinkedHashMap来保持插入顺序并去除重复
        Map<String, JSONObject> map = new LinkedHashMap<>();

        // 将每个JSONObject转换成字符串，并用作Map的键
        for (int i = 0; i < jsonArray.size(); i++) {
            try {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String jsonString = jsonObject.toString();
                map.putIfAbsent(jsonString, jsonObject);
            } catch (Exception exception) {
                // Handle any exceptions that might occur during the process.
                System.err.println("Error processing JSON object: " + exception.getMessage());
            }
        }

        // 将Map的值转换回List
        return new JSONArray(new ArrayList<>(map.values()));
    }

    /**
     * 返回两个集合的差集。该集合包含在listA中但不在listB中的所有元素。
     * @param listA 第一个集合
     * @param listB 第二个集合
     * @return 差集
     */
    public static List<String> listReduceList(List<String> listA, List<String> listB) {
        listA = fixedNullList(listA);
        listB = fixedNullList(listB);

        if (isEmptyObj(listA) || isEmptyObj(listB)) return listA;

        Set<String> result = new HashSet<>(listA);
        //result.removeAll(listB);
        listB.forEach(result::remove);
        return new ArrayList<>(result);
    }

    /**
     * 将任意类型的 Json字符串 转为 JSONArray
     */
    public static JSONArray toJsonArray(String jsonString){
        if (jsonString == null)
            return new JSONArray();

        return JSONArray.parseArray(jsonString);
    }

    /**
     * 将任意类型的 Json字符串 转为 Json 对象
     */
    public static JSONObject toJsonObject(String jsonString){
        if (jsonString == null)
            return new JSONObject();

        return JSONObject.parseObject(jsonString);
    }


    /**
     * 将JsonArray 转为 List<String>
     */
    public static List<String> toStringList(JSONArray array){
        if (isEmptyObj(array)) return new ArrayList<>();

        return array.toList(String.class);
    }

    /**
     * 将JsonArrayString 转为 List<String>
     */
    public static List<String> toStringList(String jsonArrayString){
        return toStringList(toJsonArray(jsonArrayString));
    }

    /**
     * 格式化Json数据为可输出的状态
     */
    public static String stringJsonArrayFormat(String jsonArrayString) {
        if (jsonArrayString == null || jsonArrayString.length()<=2 )
            return "";

        // 解析JSON数组
        JSONArray jsonArray = toJsonArray(jsonArrayString);
        StringBuilder formattedString = new StringBuilder();
        for (Object item : jsonArray) {
            if (item instanceof String) {
                formattedString.append((String) item).append("\n");
            } else {
                throw new IllegalArgumentException("JSONArray contains non-string element.");
            }
        }
        return formattedString.toString();
    }

    /**
     * 合并两个 List<String> 并去重
     */
    public static List<String> listAddList(List<String> listA, List<String> listB) {
        listA = fixedNullList(listA);
        listB = fixedNullList(listB);

        Set<String> uniqueSet = new LinkedHashSet<>(listA); // 创建 LinkedHashSet 并添加第一个列表的所有元素
        uniqueSet.addAll(listB); // 添加第二个列表的所有元素，重复项会被自动过滤
        return new ArrayList<>(uniqueSet); // 将 Set 转换回 List 并返回
    }

    /**
     * 合并两个 List<String> 并去重
     */
    public static JSONArray listAddList(JSONArray arrayA, JSONArray arrayB) {
        JSONArray combinedArray = new JSONArray();
        combinedArray.addAll(arrayA);
        combinedArray.addAll(arrayB);
        combinedArray = CastUtils.deduplicateJsonArray(combinedArray);
        return combinedArray;
    }


    /**
     * 字符串转列表
     */
    public static List<String> getUniqueLines(String text) {
        if (isEmptyObj(text)) {
            return new ArrayList<>();
        }
        //自动处理换行符
        text = text.replace("\r\n","\n");
        // 分割字符串
        String[] lines = text.split("\n");
        // 转换为Set以去除重复项
        Set<String> uniqueSet = new LinkedHashSet<>(Arrays.asList(lines));
        // 转换回List并返回
        return new ArrayList<>(uniqueSet);
    }

    /**
     * 合并新旧列表并去重返回
     * @param newUrlList 新的URL列表 （会自动提取RootUrl）
     * @param rawList 原始的配置文件列表
     * @return
     */
     public static List<String> addUrlsRootUrlToList(List<String> newUrlList, List<String> rawList) {
        //0、获取所有rootUrl
        Set<String> rootUrlSet = new HashSet<>();
        for (String url: newUrlList){
            HttpUrlInfo urlInfo = new HttpUrlInfo(url);
            rootUrlSet.add(urlInfo.getRootUrlUsual());
        }
        //1、加入到黑名单列表
        //合并原来的列表
        rootUrlSet.addAll(rawList);

        return new ArrayList<>(rootUrlSet);
    }

    public static List<String> getRootUrlList(List<String> newUrlList) {
        //0、获取所有rootUrl
        Set<String> rootUrlSet = new HashSet<>();
        for (String url: newUrlList){
            HttpUrlInfo urlInfo = new HttpUrlInfo(url);
            rootUrlSet.add(urlInfo.getRootUrlUsual());
        }
        return new ArrayList<>(rootUrlSet);
    }


    /**
     * 解析 响应体 获取 302 URL
     */
    public static String parseRespRedirectUrl(byte[] headerBytes) {
        String redirectUrl = null;
        if (headerBytes.length>0) {
            HelperPlus helperPlus = HelperPlus.getInstance();
            redirectUrl = helperPlus.getHeaderValueOf(true, headerBytes, "Location");
        }
        return redirectUrl;
    }

    /**
     * 判断字符串|集合|Map类型 是否为null||为空
     */
    public static boolean isEmptyObj(Object obj) {
        if (obj == null) {
            return true;
        } else if (obj instanceof String && ((String) obj).trim().isEmpty()) {
            return true;
        } else if (obj instanceof Collection && ((Collection<?>) obj).isEmpty()) {
            return true;
        } else if (obj instanceof Map && ((Map<?, ?>) obj).isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * 判断字符串|集合|Map类型 是否为null||为空
     */
    public static boolean isNotEmptyObj(Object obj) {
        return !isEmptyObj(obj);
    }

    //还原 Map<String,Array> 格式
    public static HashMap<String, JSONArray> toUrlInfoArrayMap(String jsonString) {
        // 使用 FastJSON2 的 parseObject 方法，传入 HashMap 的具体类型
        HashMap<String, JSONArray> urlInfoArrayMap = JSONObject.parseObject(jsonString, new TypeReference<HashMap<String, JSONArray>>(){});
        return urlInfoArrayMap;
    }

    public static HashMap<String, JSONArray> mapAddMap(HashMap<String, JSONArray> map1, HashMap<String, JSONArray> map2) {
        HashMap<String, JSONArray> map = new HashMap<>();
        if (map1.size()>0) map.putAll(map1);
        if (map2.size()>0) map.putAll(map2);
        return map;
    }

    public static String escapeHtml(String input) {
        if(input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * 格式化Json数据为可输出的状态
     */
    public static String infoJsonArrayFormatHtml(String jsonArrayString) {
        if (jsonArrayString == null || jsonArrayString.length()<=2 )
            return "";

        JSONArray jsonArray = JSONArray.parseArray(jsonArrayString);
        StringBuilder formattedResult = new StringBuilder();

        for (Object obj : jsonArray) {
            if (obj instanceof JSONObject) {
                JSONObject jsonObject = (JSONObject) obj;

                // 使用String.format进行格式化
                String formattedItem = String.format(
                        "# ############# type: %s #############<br>" +
                                "# describe: <span style='color: $color$};'>%s</span><br>" +
                                "# value: <span style='color: $color$};'>%s</span><br>" +
                                "# matchType: %s<br>" +
                                "# accuracy: %s<br>" +
                                "# important: %s<br>"
                        ,
                        jsonObject.getString(AnalyseInfo.type),
                        jsonObject.getString(AnalyseInfo.describe),
                        escapeHtml(jsonObject.getString(AnalyseInfo.value)),
                        escapeHtml(jsonObject.getString(AnalyseInfo.matchType)),
                        jsonObject.getString(AnalyseInfo.accuracy),
                        jsonObject.getString(AnalyseInfo.important)
                );

                //进行颜色标记
                String color = jsonObject.getBoolean("important") ? "red" : "blue";
                formattedItem = formattedItem.replace("$color$",color);
                formattedResult.append(formattedItem);
            }
        }

        return formattedResult.toString();
    }

    /**
     * 格式化Json数据为可输出的状态
     */
    public static String urlInfoJsonArrayMapFormatHtml(String urlInfoJsonArrayMapString) {
        if (urlInfoJsonArrayMapString == null || urlInfoJsonArrayMapString.length()<=2 )
            return "";

        HashMap<String, JSONArray> urlInfoJsonArrayMap = toUrlInfoArrayMap(urlInfoJsonArrayMapString);
        StringBuilder formattedResult = new StringBuilder();

        // 遍历 HashMap
        for (Map.Entry<String, JSONArray> entry : urlInfoJsonArrayMap.entrySet()) {
            String infoUrl = entry.getKey();
            JSONArray jsonArray = entry.getValue();
            for (Object obj : jsonArray) {
                if (obj instanceof JSONObject) {
                    JSONObject jsonObject = (JSONObject) obj;

                    // 使用String.format进行格式化
                    String formattedItem = String.format(
                            "# ############# type: %s #############<br>" +
                                    "# Describe: <span style='color: $color$};'>%s</span><br>" +
                                    "# Value: <span style='color: $color$};'>%s</span><br>" +
                                    "# Match: %s<br>" +
                                    "# Accuracy: %s<br>" +
                                    "# Important: %s<br>" +
                                    "# FromUrl: %s<br>"
                            ,
                            jsonObject.getString(AnalyseInfo.type),
                            jsonObject.getString(AnalyseInfo.describe),
                            escapeHtml(jsonObject.getString(AnalyseInfo.value)),
                            escapeHtml(jsonObject.getString(AnalyseInfo.matchType)),
                            jsonObject.getString(AnalyseInfo.accuracy),
                            jsonObject.getString(AnalyseInfo.important),
                            infoUrl
                    );

                    //进行颜色标记
                    String color = jsonObject.getBoolean("important") ? "red" : "blue";
                    formattedItem = formattedItem.replace("$color$",color);
                    formattedResult.append(formattedItem);
                }
            }
        }
        return formattedResult.toString();
    }

    //Url 列 转 URL 状态码Json
    public static HashMap<String, JSONObject> toUrlStatusJsonMap(List<String> urlList) {
        JSONObject defaultJson = new JSONObject() {{
            put("status", -1);
            put("length", -1);
        }};

        // 使用 FastJSON2 的 parseObject 方法，传入 HashMap 的具体类型
        HashMap<String, JSONObject> urlStatusArrayMap = new HashMap<>();
        for (String url:urlList){
            for (String method:BurpExtender.CONF_RECURSE_REQ_HTTP_METHODS){
                String urlWithMethod = String.format("%s %s %s", url, Constants.SPLIT_SYMBOL, method);
                urlStatusArrayMap.put(urlWithMethod,defaultJson);
            }
        }
        return urlStatusArrayMap;
    }

    /**
     * json对象还原到Url Map对象
     */
    public static HashMap<String, JSONObject> toUrlStatusJsonMap(String jsonString) {
        if (isEmptyObj(jsonString) || jsonString.length() < 2){
            return new HashMap<>();
        }
        // 使用 FastJSON2 的 parseObject 方法，传入 HashMap 的具体类型
        HashMap<String, JSONObject> urlInfoArrayMap = JSONObject.parseObject(jsonString, new TypeReference<HashMap<String, JSONObject>>(){});
        return urlInfoArrayMap;
    }


    //更新两个 UrlStatus Map
    public static HashMap<String, JSONObject> updateUrlStatusMap(HashMap<String, JSONObject> map1, HashMap<String, JSONObject> map2) {
        if (map1.isEmpty()) return map2;
        if (map2.isEmpty()) return map1;

        HashMap<String, JSONObject> map = new HashMap<>(map1);
        // 遍历 HashMap 的条目集合
        for (Map.Entry<String, JSONObject> entry : map2.entrySet()) {
            String urlWithMethod = entry.getKey();
            JSONObject urlStatusJson = entry.getValue();
            Integer status = urlStatusJson.getInteger("status");
            Integer length = urlStatusJson.getInteger("length");
            if (status > -1 || length > -1){
                map.put(urlWithMethod, urlStatusJson);
            }
        }
        return map;
    }

    /**
     * 将HashMap<String, JSONObject>按照String键排序，并返回一个新的SortedMap。
     *
     * @param urlStatusJsonMap 原始未排序的HashMap
     * @return 按照String键排序后的SortedMap
     */
    public static SortedMap<String, JSONObject> sortUrlStatusJsonMap(HashMap<String, JSONObject> urlStatusJsonMap) {
        // 创建一个TreeMap用于存放已排序的数据，默认会按照键的自然顺序排序
        TreeMap<String, JSONObject> sortedMap = new TreeMap<>(urlStatusJsonMap);
        return sortedMap;
    }


    /**
     * 序列化已排序的Map到JSON字符串，并保持键值对的顺序。
     *
     * @param sortedMap 已排序的Map
     * @return JSON格式的字符串
     */
    public static String toJsonStringWithOrder(SortedMap<String, JSONObject> sortedMap) {
        // 使用JSONWriter.Feature.MapSortField特性来保持输出顺序
        return JSON.toJSONString(sortedMap, JSONWriter.Feature.MapSortField);
    }


    //转换Json字符串为可以输出的HTML格式
    public static String stringUrlStatusMapFormatHtml(String jsonArrayString) {
        if (jsonArrayString == null || jsonArrayString.length()<=2 )
            return "";

        // 解析JSON数组
        // HashMap<String, JSONObject> urlStatusJsonMap = toUrlStatusJsonMap(jsonArrayString);
        //解析JSON并自动排序
        SortedMap<String, JSONObject> urlStatusJsonMap = sortUrlStatusJsonMap(toUrlStatusJsonMap(jsonArrayString));

        // 开始构建HTML表格
        StringBuilder htmlTableBuilder = new StringBuilder();
        htmlTableBuilder.append("<table border='1' cellpadding='5' cellspacing='0'>");
        htmlTableBuilder.append("<thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Length</th></tr></thead>");
        htmlTableBuilder.append("<tbody>");

        // 遍历JSON对象并添加行到表格中
        for (Map.Entry<String, JSONObject> entry : urlStatusJsonMap.entrySet()) {
            String urlWithMethod = entry.getKey();
            JSONObject urlStatusJson = entry.getValue();
            Integer status = urlStatusJson.getInteger("status");
            Integer length = urlStatusJson.getInteger("length");

            // 分离URL和请求方法
            String[] parts = urlWithMethod.split(Constants.SPLIT_SYMBOL);
            String url = parts[0].trim();
            String method = parts.length > 1 ? parts[1].trim() : "NULL";

            // 添加一行到HTML表格，直接应用内联样式
            String format = String.format(
                    "<tr style='%s'><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>\n",
                    status != -1 ? "font-weight: bold; background-color: #f2f2f2;" : "", // 如果需要加粗，则添加内联样式
                    escapeHtml(url), method, status, length
            );

            htmlTableBuilder.append(format);
        }

        htmlTableBuilder.append("</tbody>");
        htmlTableBuilder.append("</table>");

        return htmlTableBuilder.toString();
    }


    /**
     * 将列表中的所有字符串元素转换为大写。
     * @param list 要转换的字符串列表
     * @return 包含大写字符串的新列表
     */
    public static List<String> elementsToUpper(List<String> list) {
        List<String> upperCaseList = new ArrayList<>();
        for (String item : list) {
            upperCaseList.add(item.toUpperCase().trim());
        }
        return upperCaseList;
    }

    /**
     * 删除字符串中的所有空白行（只包含一个或多个空格的行）。
     *
     * @param prettyJson 包含多行的字符串
     * @return 删除空白行后的字符串
     */
    public static String removeJsonForMat(String prettyJson) {
        prettyJson = prettyJson.replace("{","").replace("}","");

        // 使用换行符分割字符串
        List<String> lines = new ArrayList<>(Arrays.asList(prettyJson.split("\\r?\\n")));

        // 过滤掉空白行
        List<String> filteredLines = new ArrayList<>();
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                filteredLines.add(line);
            }
        }

        // 将过滤后的行重新组合成一个字符串
        return String.join(System.lineSeparator(), filteredLines);
    }


    /**
     * 列表转字符串（支持常见类型）
     * @return 转换后的字符串，格式为 "[item1, item2, item3]"
     */
    public static <T> String listToString(List<T> list) {
        if (list == null || list.isEmpty()) {
            return "[]"; // 如果列表为空或为 null，返回空数组的表示形式
        }
        return Arrays.toString(list.toArray());
    }

    public static <T> String setToString(Set<T> set) {
        if (set == null || set.isEmpty()) {
            return "[]"; // 如果列表为空或为 null，返回空数组的表示形式
        }
        return Arrays.toString(set.toArray());
    }

}
