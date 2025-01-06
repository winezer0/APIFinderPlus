package database;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.*;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static utils.BurpPrintUtils.LOG_ERROR;
import static utils.BurpPrintUtils.stderr_println;

public class AnalyseHostResultTable {
    //数据表名称
    public static String tableName = "ANALYSE_HOST_RESULT";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS "+ tableName +" (\n"
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "root_url TEXT NOT NULL,\n"  //请求URL

            + "find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + "find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量
            + "has_important INTEGER DEFAULT 0,\n"    //是否存在重要信息

            + "find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + "find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + "find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + "find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + "find_api TEXT DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + "find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "path_to_url TEXT DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + "path_to_url_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "unvisited_url TEXT DEFAULT '',\n"      //合并所有URL 并去除已经访问过的URL (Json格式)
            + "unvisited_url_num INTEGER DEFAULT -1,\n"   //合并所有URL 并去除已经访问过的URL的数量

            //TODO 实现所有URL的简单状态码显示

            + "all_url_status TEXT DEFAULT '',\n"      //合并所有URL MAP<url,status json> 格式
            + "all_url_num INTEGER DEFAULT -1,\n"

            + "basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?
            + "run_status TEXT NOT NULL DEFAULT 'RUN_STATUS'".replace("RUN_STATUS", Constants.HANDLE_WAIT)

            + ");";



    /**
     * 为每个HOST插入分析结果, 此时不包含动态生成的URL
     * @param analyseHostResultModel 基于host的结果模型
     * @param addApiList 是否将直接拼接的 apiList 加入到未访问URL列表中
     * @return
     */
    public static synchronized int insertOrUpdateAnalyseHostResult(AnalyseHostResultModel analyseHostResultModel, boolean addApiList){
        String rootUrl = analyseHostResultModel.getRootUrl();
        HashMap<String, JSONArray> urlInfoArrayMap = analyseHostResultModel.getUrlInfoArrayMap();
        List<String> urlList = analyseHostResultModel.getUrlList();
        List<String> pathList = analyseHostResultModel.getPathList();
        List<String> apiList = analyseHostResultModel.getApiList();
        Boolean hasImportant = analyseHostResultModel.getHasImportant();
        List<String> unvisitedUrlList = analyseHostResultModel.getUnvisitedUrlList(addApiList);

        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String selectSql = "SELECT * FROM "+ tableName +" WHERE root_url = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt1 = conn.prepareStatement(selectSql)) {
            // 检查记录是否存在
            stmt1.setString(1, rootUrl);
            ResultSet rs = stmt1.executeQuery();
            if (!rs.next()) {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO "+ tableName + " " +
                        "(root_url, find_info, find_info_num, has_important, " +
                        "find_url, find_url_num, find_path, find_path_num, find_api, find_api_num, " +
                        "unvisited_url, unvisited_url_num, run_status) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement stmt2 = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    stmt2.setString(1, rootUrl);

                    stmt2.setString(2, CastUtils.toJsonString(urlInfoArrayMap));
                    stmt2.setInt(3, urlInfoArrayMap.size());
                    stmt2.setBoolean(4, hasImportant);

                    stmt2.setString(5, CastUtils.toJsonString(urlList));
                    stmt2.setInt(6, urlList.size());

                    stmt2.setString(7, CastUtils.toJsonString(pathList));
                    stmt2.setInt(8, pathList.size());

                    stmt2.setString(9, CastUtils.toJsonString(apiList));
                    stmt2.setInt(10, apiList.size());

                    stmt2.setString(11, CastUtils.toJsonString(unvisitedUrlList));
                    stmt2.setInt(12,unvisitedUrlList.size());

                    stmt2.setString(13,Constants.HANDLE_WAIT); //设置状态为等待处理

                    stmt2.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = stmt2.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }

                return 0;
            } else {
                int id = rs.getInt("id");
                HashMap<String, JSONArray> oldUrlInfoArrayMap = CastUtils.toUrlInfoArrayMap(rs.getString("find_info"));
                Boolean oldHasImportant = rs.getBoolean("has_important");
                List<String> oldUrlList = CastUtils.toStringList(rs.getString("find_url"));
                List<String> oldPathList = CastUtils.toStringList(rs.getString("find_path"));
                List<String> oldApiList = CastUtils.toStringList(rs.getString("find_api"));
                List<String> oldUnvisitedUrlList = CastUtils.toStringList(rs.getString("unvisited_url"));

                // 记录存在 合并旧的数据 更新记录
                String updateSql = "UPDATE " + tableName + " SET " +
                        "find_info = ?, find_info_num = ?, has_important = ?, " +
                        "find_url = ?, find_url_num = ?, find_path = ?, find_path_num = ?, find_api = ?, find_api_num = ?, " +
                        "unvisited_url = ?, unvisited_url_num = ? WHERE root_url = ?";

                try (PreparedStatement stmt2 = conn.prepareStatement(updateSql)) {
                    //find_info
                    HashMap<String, JSONArray> newUrlInfoArrayMap = CastUtils.mapAddMap(oldUrlInfoArrayMap, urlInfoArrayMap);
                    stmt2.setString(1, CastUtils.toJsonString(newUrlInfoArrayMap));
                    stmt2.setInt(2, newUrlInfoArrayMap.size());

                    //has_important
                    stmt2.setBoolean(3, hasImportant||oldHasImportant);

                    List<String> newUrlList = CastUtils.listAddList(urlList, oldUrlList);
                    stmt2.setString(4, CastUtils.toJsonString(newUrlList));
                    stmt2.setInt(5, newUrlList.size());

                    List<String> newPathList = CastUtils.listAddList(pathList, oldPathList);
                    stmt2.setString(6, CastUtils.toJsonString(newPathList));
                    stmt2.setInt(7, newPathList.size());

                    List<String> newApiList = CastUtils.listAddList(apiList, oldApiList);
                    stmt2.setString(8, CastUtils.toJsonString(newApiList));
                    stmt2.setInt(9, newApiList.size());

                    //计算所有新增的URL
                    List<String> oldAddUrlList = CastUtils.listAddList(oldUrlList, oldApiList); //历史上该主机采集的所有URL
                    unvisitedUrlList = CastUtils.listReduceList(unvisitedUrlList,oldAddUrlList); //首先排除所有历史采集的URL
                    List<String> newUnvisitedUrlList = CastUtils.listAddList(unvisitedUrlList, oldUnvisitedUrlList); //合并查询前未访问URL
                    stmt2.setString(10, CastUtils.toJsonString(newUnvisitedUrlList));
                    stmt2.setInt(11, newUnvisitedUrlList.size());

                    stmt2.setString(12, rootUrl);

                    stmt2.executeUpdate();

                    // 如果需要获取更新记录的ID，可以查询主键
                    generatedId = id; // 假设id是主键且名为"id"
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; //返回ID值，无论是更新还是插入
    }

    /**
     * 获取对应ID的动态 URL （当前是动态Path计算URL、未访问URL）
     */
    public static synchronized PathToUrlsModel fetchDynamicUrlsDataById(int id){
        PathToUrlsModel pathToUrlsModel = null;

        String selectSQL = "SELECT id,path_to_url,unvisited_url,basic_path_num FROM  "+ tableName +" WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                pathToUrlsModel = new PathToUrlsModel(
                        rs.getInt("id"),
                        rs.getInt("basic_path_num"),
                        rs.getString("path_to_url"),
                        rs.getString("unvisited_url")
                );
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] path_to_url and unvisited_url By Id: %s", tableName, e.getMessage()));
        }
        return pathToUrlsModel;
    }

    /**
     * 基于ID更新动态URl数据
     */
    public static synchronized int updateDynamicUrlsDataByModel(PathToUrlsModel dynamicUrlModel){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE "+ tableName +
                " SET path_to_url = ?, path_to_url_num = ?, unvisited_url = ?, unvisited_url_num = ?, basic_path_num = ?, run_status = ? WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {

            stmt.setString(1, CastUtils.toJsonString(dynamicUrlModel.getPathToUrls()));
            stmt.setInt(2, dynamicUrlModel.getPathToUrls().size());

            stmt.setString(3, CastUtils.toJsonString(dynamicUrlModel.getUnvisitedUrls()));
            stmt.setInt(4, dynamicUrlModel.getUnvisitedUrls().size());

            stmt.setInt(5, dynamicUrlModel.getBasicPathNum());

            stmt.setString(6, Constants.HANDLE_WAIT);//更新状态为待处理

            stmt.setInt(7, dynamicUrlModel.getId());

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                generatedId = dynamicUrlModel.getId();
            }

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update [%] Path Data: %s", tableName, e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    /**
     * 基于ID更新 PathToUrl 的基础计数数据
     */
    public static synchronized int updateDynamicUrlsBasicNumById(int id, int basicPathNum){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE "+ tableName +"  SET basic_path_num = ? WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {

            stmt.setInt(1, basicPathNum);
            stmt.setInt(2, id);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                generatedId = id;
            }

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update [%] Basic Path Num: %s",tableName, e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    /**
     * 获取多条 存在 Path 并且没有 动态计算过的 path数据
     */
    public static synchronized List<FindPathModel> fetchPathDataByRootUrl(List<String> rootUrls){
        List<FindPathModel> findPathModelList = new ArrayList<>();

        if (rootUrls.isEmpty()) return findPathModelList;

        String selectSQL = ("SELECT * FROM " + tableName + " WHERE root_url IN $buildInParamList$;")
                .replace("$buildInParamList$", DBService.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 1, rootUrls.get(i));
            }
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                FindPathModel findPathModel =  new FindPathModel(
                        rs.getInt("id"),
                        rs.getString("root_url"),
                        rs.getString("find_path")
                );

                findPathModelList.add(findPathModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Path Data By RootUrl List: %s", tableName, e.getMessage()));
        }
        return findPathModelList ;
    }

    /**
     * 获取 指定 rootUrl 对应的 所有 分析结果 数据
     */
    public static synchronized BasicHostTableTabDataModel fetchHostResultByRootUrl(String rootUrl){
        BasicHostTableTabDataModel tabDataModel = null;
        String selectSQL = "SELECT * FROM " + tableName +" WHERE root_url = ?;";
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, rootUrl);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    tabDataModel = new BasicHostTableTabDataModel(
                            rs.getString("root_url"),
                            rs.getString("find_info"),
                            rs.getString("find_url"),
                            rs.getString("find_path"),
                            rs.getString("find_api"),
                            rs.getString("path_to_url"),
                            rs.getString("unvisited_url"),
                            rs.getString("all_url_status")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Host Analyse Result Data By RootUrl: %s",  e.getMessage()));
        }
        return tabDataModel;
    }

    /**
     * 获取 指定 rootUrls 对应的 所有 分析结果 数据
     */
    public static synchronized List<BasicHostTableTabDataModel> fetchHostResultByRootUrls(List<String> rootUrls){
        List<BasicHostTableTabDataModel> tabDataModels = new ArrayList<>();
        String selectSQL = ("SELECT * FROM " + tableName +" WHERE root_url IN $buildInParamList$;")
                .replace("$buildInParamList$", DBService.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {

            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 1, rootUrls.get(i));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    BasicHostTableTabDataModel tabDataModel = new BasicHostTableTabDataModel(
                            rs.getString("root_url"),
                            rs.getString("find_info"),
                            rs.getString("find_url"),
                            rs.getString("find_path"),
                            rs.getString("find_api"),
                            rs.getString("path_to_url"),
                            rs.getString("unvisited_url"),
                            rs.getString("all_url_status")
                    );
                    tabDataModels.add(tabDataModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Host Analyse Result Data By RootUrl: %s",  e.getMessage()));
        }
        return tabDataModels;
    }

    /**
     * 基于ID更新动态URl数据
     */
    public static synchronized int updateUrlsStatusByRootUrl(String rootUrl, HashMap<String, JSONObject> allUrlStatus, Integer allUrlNum){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE "+ tableName + " SET all_url_status = ?, all_url_num = ? WHERE root_url = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {

            stmt.setString(1, CastUtils.toJsonString(allUrlStatus));
            //stmt.setInt(2, allUrlStatus.keySet().size());
            stmt.setInt(2, allUrlNum);
            stmt.setString(3, rootUrl);

            int affectedRows = stmt.executeUpdate();
            generatedId = affectedRows;
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update [%] Urls Status By RootUrl: %s", tableName, e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }
}
