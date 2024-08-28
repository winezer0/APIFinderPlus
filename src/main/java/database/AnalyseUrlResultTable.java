package database;

import com.alibaba.fastjson2.JSONArray;
import model.*;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;

import static utils.BurpPrintUtils.*;

public class AnalyseUrlResultTable {
    //数据表名称
    public static String tableName = "ANALYSE_URL_RESULT";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS "+ tableName +" (\n"
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "msg_hash TEXT UNIQUE,\n"  //请求Hash信息
            + "req_url TEXT NOT NULL,\n"  //请求URL
            + "req_host_port TEXT NOT NULL,\n"  //请求HOST PORT

            + "find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + "find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + "find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + "find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + "find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + "find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量
            + "has_important INTEGER DEFAULT 0,\n"    //是否存在重要信息

            + "find_api TEXT DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + "find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "path_to_url TEXT DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + "path_to_url_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "unvisited_url TEXT DEFAULT '',\n"      //合并所有URL 并去除已经访问过的URL (Json格式)
            + "unvisited_url_num INTEGER DEFAULT -1,\n"   //合并所有URL 并去除已经访问过的URL的数量

            + "basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'"
            .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)

            + ");";

    /**
     * 插入第一次分析完毕的 URL和PATH结果, 此时不包含动态生成的URL
     * @param msgInfo
     * @param analyseInfo
     * @return
     */
    public static synchronized int insertBasicAnalyseResult(HttpMsgInfo msgInfo, AnalyseUrlResultModel analyseInfo){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String selectSql = "SELECT id FROM "+ tableName +" WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt1 = conn.prepareStatement(selectSql)) {
            // 检查记录是否存在
            stmt1.setString(1, msgInfo.getMsgHash());
            ResultSet rs = stmt1.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO "+ tableName +"" +
                        " (msg_hash, req_url, req_host_port, find_url, find_url_num, find_path, find_path_num," +
                        " find_info, find_info_num, find_api, find_api_num, unvisited_url, unvisited_url_num, run_status, has_important)" +
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement stmt2 = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    stmt2.setString(1, msgInfo.getMsgHash());
                    stmt2.setString(2, msgInfo.getUrlInfo().getRawUrlUsual());
                    stmt2.setString(3, msgInfo.getUrlInfo().getHostPort());

                    stmt2.setString(4, CastUtils.toJsonString(analyseInfo.getUrlList()));
                    stmt2.setInt(5, analyseInfo.getUrlList().size());

                    stmt2.setString(6, CastUtils.toJsonString(analyseInfo.getPathList()));
                    stmt2.setInt(7, analyseInfo.getPathList().size());

                    stmt2.setString(8, CastUtils.toJsonString(analyseInfo.getInfoArray()));
                    stmt2.setInt(9, analyseInfo.getInfoArray().size());

                    stmt2.setString(10, CastUtils.toJsonString(analyseInfo.getApiList()));
                    stmt2.setInt(11, analyseInfo.getApiList().size());

                    //TODO 需要删除 此处的 UnvisitedUrl 相关代码
                    stmt2.setString(12, CastUtils.toJsonString(analyseInfo.getUnvisitedUrl()));
                    stmt2.setInt(13, analyseInfo.getUnvisitedUrl().size());

//                    //在这个响应中没有找到 PATH 数据,就修改状态为无需解析
//                    if (analyseInfo.getPathList().size() > 0){
//                        stmt2.setString(14, Constants.ANALYSE_WAIT);
//                    } else {
//                        stmt2.setString(14, Constants.ANALYSE_END);
//                    }

                    //设置初始的响应状态为 等待处理
                    stmt2.setString(14, Constants.ANALYSE_WAIT);

                    stmt2.setBoolean(15, analyseInfo.getHasImportant());

                    stmt2.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = stmt2.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; //返回ID值，无论是更新还是插入
    }


    /**
     * 根据运行状态取获取对应请求ID
     * @return
     */
    public static synchronized List<String> fetchMsgHashByRunStatusIsWait(int limit){
        return CommonSql.fetchMsgHashByRunStatus(tableName, limit, Constants.ANALYSE_WAIT);
    }


    //更新数据对应状态
    public static int updateStatusRunIngByMsgHashList(List<String> msgHashList) {
        return CommonSql.updateStatusByMsgHashList(tableName, msgHashList, Constants.ANALYSE_ING);
    }

    //更新数据对对应状态
    public static int updateStatusRunEndByMsgHashList(List<String> msgHashList) {
        return CommonSql.updateStatusByMsgHashList(tableName, msgHashList, Constants.ANALYSE_END);
    }

    /**
     * 获取 指定 msgHashList 对应的 所有 分析结果 数据
     * @return
     */
    public static synchronized List<AnalyseUrlResultModel> fetchResultByMsgHashList(List<String> msgHashList){
        List<AnalyseUrlResultModel> AnalyseUrlResultModels = new ArrayList<>();

        if (msgHashList.isEmpty()) return AnalyseUrlResultModels;

        String selectSQL = "SELECT * FROM " + tableName + " WHERE msg_hash IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                AnalyseUrlResultModel tabDataModel = new AnalyseUrlResultModel(
                        rs.getString("req_url"),
                        rs.getString("find_info"),
                        rs.getString("find_url"),
                        rs.getString("find_path"),
                        rs.getString("find_api"),
                        rs.getBoolean("has_important")
                );
                AnalyseUrlResultModels.add(tabDataModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Result Data By MsgHash List: %s",tableName, e.getMessage()));
        }
        return AnalyseUrlResultModels;
    }


    /**
     * 获取 指定 msgHash 对应的 所有 分析结果 数据, 用于填充 UI 表的下方 tab 数据
     */
    public static synchronized UrlTableTabDataModel fetchResultByMsgHash(String msgHash){
        UrlTableTabDataModel tabDataModel = null;

        String selectSQL = "SELECT * FROM "+ tableName +" WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, msgHash);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    tabDataModel = new UrlTableTabDataModel(
                            rs.getString("msg_hash"),
                            rs.getString("find_url"),
                            rs.getString("find_path"),
                            rs.getString("find_info"),
                            rs.getString("find_api"),
                            rs.getString("path_to_url"),
                            rs.getString("unvisited_url")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Analyse Result Data By MsgHash: %s", e.getMessage()));
        }
        return tabDataModel;
    }

    /**
     * 获取多条 存在 Path 并且没有 动态计算过的 path数据
     */
    public static synchronized List<FindPathModel> fetchPathDataByMsgHashList(List<String> msgHashList){
        List<FindPathModel> findPathModelList = new ArrayList<>();

        if (msgHashList.isEmpty()) return findPathModelList;

        String selectSQL = "SELECT * FROM " + tableName + " WHERE msg_hash IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                FindPathModel findPathModel =  new FindPathModel(
                        rs.getInt("id"),
                        rs.getString("req_url"),
                        rs.getString("req_host_port"),
                        rs.getString("find_path")
                );

                findPathModelList.add(findPathModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Path Data By MsgHash List: %s", tableName, e.getMessage()));
        }
        return findPathModelList ;
    }

    /**
     * 获取对应ID的动态 URL （当前是动态Path计算URL、未访问URL）
     * @param id
     * @return
     */
    public static synchronized DynamicUrlsModel fetchDynamicUrlsDataById(int id){
        DynamicUrlsModel dynamicUrlsModel = null;

        String selectSQL = "SELECT id,path_to_url,unvisited_url,basic_path_num FROM  "+ tableName +" WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                dynamicUrlsModel = new DynamicUrlsModel(
                        rs.getInt("id"),
                        rs.getInt("basic_path_num"),
                        rs.getString("path_to_url"),
                        rs.getString("unvisited_url")
                );
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] path_to_url and unvisited_url By Id: %s", tableName, e.getMessage()));
        }
        return dynamicUrlsModel;
    }

    /**
     * 基于ID更新 PathToUrl 的基础计数数据
     * @param id
     * @param basicPathNum
     * @return
     */
    public static synchronized int updateDynamicUrlsBasicNum(int id, int basicPathNum){
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
            stderr_println(LOG_ERROR, String.format("[-] Error update Path Data: %s", e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    /**
     * 基于ID更新动态URl数据
     * @param dynamicUrlModel
     * @return
     */
    public static synchronized int updateDynamicUrlsModelById(DynamicUrlsModel dynamicUrlModel){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE "+ tableName +
                " SET path_to_url = ?, path_to_url_num = ?," +
                " unvisited_url = ?, unvisited_url_num = ?, basic_path_num = ?" +
                " WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {

            stmt.setString(1, CastUtils.toJsonString(dynamicUrlModel.getPathToUrls()));
            stmt.setInt(2, dynamicUrlModel.getPathToUrls().size());

            stmt.setString(3, CastUtils.toJsonString(dynamicUrlModel.getUnvisitedUrls()));
            stmt.setInt(4, dynamicUrlModel.getUnvisitedUrls().size());

            stmt.setInt(5, dynamicUrlModel.getBasicPathNum());
            stmt.setInt(6, dynamicUrlModel.getId());

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                generatedId = dynamicUrlModel.getId();
            }

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update Path Data: %s", e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    /**
     * 获取 所有未访问URl (unvisited_url_num > 0)
     * @return
     */
    public static synchronized List<UnVisitedUrlsModel> fetchAllUnVisitedUrls( ){
        List<UnVisitedUrlsModel> list = new ArrayList<>();

        String selectSQL = "SELECT id, msg_hash, req_url, unvisited_url FROM  "+ tableName + " WHERE unvisited_url_num > 0 ORDER BY id ASC;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    UnVisitedUrlsModel unVisitedUrlsModel = new UnVisitedUrlsModel(
                            rs.getInt("id"),
                            rs.getString("msg_hash"),
                            rs.getString("req_url"),
                            rs.getString("unvisited_url")
                    );
                    list.add(unVisitedUrlsModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] All UnVisited Urls: %s", tableName, e.getMessage()));
        }
        return list;
    }

    /**
     * 实现 基于 ID 更新 unvisitedUrls
     * @param unVisitedUrlsModel
     * @return
     */
    public static synchronized int updateUnVisitedUrlsById(UnVisitedUrlsModel unVisitedUrlsModel) {
        int affectedRows = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE " + tableName +"  SET unvisited_url = ?, unvisited_url_num = ? WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            stmt.setString(1, CastUtils.toJsonString(unVisitedUrlsModel.getUnvisitedUrls()));
            stmt.setInt(2, unVisitedUrlsModel.getUnvisitedUrls().size());
            stmt.setInt(3, unVisitedUrlsModel.getId());
            affectedRows = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update unvisited Urls By Id: %s", e.getMessage()));
        }
        return affectedRows;
    }

    /**
     * 实现 基于 MsgHash 更新 unvisitedUrls
     * @param unVisitedUrlsModel
     * @return
     */
    public static synchronized int updateUnVisitedUrlsByMsgHash(UnVisitedUrlsModel unVisitedUrlsModel) {
        int affectedRows = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE " + tableName +"  SET unvisited_url = ?, unvisited_url_num = ? WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            stmt.setString(1, CastUtils.toJsonString(unVisitedUrlsModel.getUnvisitedUrls()));
            stmt.setInt(2, unVisitedUrlsModel.getUnvisitedUrls().size());
            stmt.setString(3, unVisitedUrlsModel.getMsgHash());
            affectedRows = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update unvisited Urls By MsgHash: %s", e.getMessage()));
        }
        return affectedRows;
    }

    /**
     * 实现 基于 msgHash 删除 unvisitedUrls
     */
    public static synchronized int clearUnVisitedUrlsByMsgHash(String msgHash) {
        int affectedRows = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE "+ tableName +"  SET unvisited_url = ?, unvisited_url_num = 0 WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            JSONArray emptyArray = new JSONArray();
            stmt.setString(1, emptyArray.toJSONString());
            stmt.setString(2, msgHash);
            affectedRows = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update unvisited Urls: %s", e.getMessage()));
        }
        return affectedRows;
    }

    /**
     * 实现 基于 msgHash 列表 删除 unvisitedUrls
     */
    public static synchronized int clearUnVisitedUrlsByMsgHashList(List<String> msgHashList) {
        int totalRowsAffected = 0;
        if (msgHashList.isEmpty()) return totalRowsAffected;

        // 构建SQL语句
        String updateSQL = "UPDATE "+ tableName + " SET unvisited_url = ?, unvisited_url_num = 0 WHERE msg_hash IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            // 设置第一个参数为JSON数组的toJSONString()
            JSONArray emptyArray = new JSONArray();
            stmt.setString(1, emptyArray.toJSONString());

            // 循环设置参数 // 开始于第二个参数位置，第一个参数已被设置
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 2, msgHashList.get(i));
            }
            // 执行更新操作并获取受影响行数
            totalRowsAffected = stmt.executeUpdate();

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error clearing unvisited URLs by msg hash list -> Error:[%s]", e.getMessage()));
        }
        return totalRowsAffected;
    }

    /**
     * 实现 基于 msgHash 列表 删除 FindApiUrl
     */
    public static synchronized int clearFindApiUrlsByMsgHashList(List<String> msgHashList) {
        int totalRowsAffected = 0;
        if (msgHashList.isEmpty()) return totalRowsAffected;

        // 构建SQL语句
        String updateSQL = "UPDATE "+ tableName + " SET find_api = ?, find_api_num = 0 WHERE msg_hash IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            // 设置第一个参数为JSON数组的toJSONString()
            JSONArray emptyArray = new JSONArray();
            stmt.setString(1, emptyArray.toJSONString());

            // 循环设置参数 // 开始于第二个参数位置，第一个参数已被设置
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 2, msgHashList.get(i));
            }

            // 执行更新操作并获取受影响行数
            totalRowsAffected = stmt.executeUpdate();

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error clearing FindApi URLs by msg hash list -> Error:[%s]", e.getMessage()));
        }
        return totalRowsAffected;
    }

    /**
     * 实现 基于 msgHash 列表 获取 unvisitedUrls 列表
     */
    public static synchronized List<UnVisitedUrlsModel> fetchUnVisitedUrlsByMsgHashList(List<String> msgHashList) {
        List<UnVisitedUrlsModel> unVisitedUrlsModels = new ArrayList<>();
        if (msgHashList.isEmpty()) return unVisitedUrlsModels;

        String selectSQL = "SELECT id, msg_hash, req_url, unvisited_url FROM "+ tableName +" WHERE msg_hash IN $buildInParameterList$;"
                .replace("$buildInParameterList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {

            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    UnVisitedUrlsModel unVisitedUrlsModel = new UnVisitedUrlsModel(
                            rs.getInt("id"),
                            rs.getString("msg_hash"),
                            rs.getString("req_url"),
                            rs.getString("unvisited_url")
                    );
                    unVisitedUrlsModels.add(unVisitedUrlsModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetching [%s] UnVisited Urls By MsgHash List: %s", tableName, e.getMessage()));
        }

        return unVisitedUrlsModels;
    }

    /**
     * 实现 基于 msgHash 列表 获取 XXX Urls 列表
     */
    public static synchronized Set<String> fetchSpecialUrlsByMsgHashList(String columnName, List<String> msgHashList) {
        Set<String> urlsSet = new LinkedHashSet<>();
        if (msgHashList.isEmpty()) return urlsSet;

        String selectSQL = "SELECT " + columnName + " FROM "+ tableName +" WHERE msg_hash IN $buildInParameterList$;"
                .replace("$buildInParameterList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {

            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    String urlJson = rs.getString(columnName);
                    List<String> urlList = CastUtils.toStringList(urlJson);
                    urlsSet.addAll(urlList);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetching [%s] [%s] Urls By MsgHash List: %s",tableName, columnName, e.getMessage()));
        }

        return urlsSet;
    }


}
