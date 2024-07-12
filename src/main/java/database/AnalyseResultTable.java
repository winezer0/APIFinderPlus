package database;

import model.*;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class AnalyseResultTable {
    //数据表名称
    static String tableName = "ANALYSE_RESULT";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT UNIQUE,\n"  //请求Hash信息
            + " req_url TEXT NOT NULL,\n"  //请求URL
            + " req_host_port TEXT NOT NULL,\n"  //请求HOST PORT

            + " find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + " find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + " find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + " find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + " find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + " find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量

            + " find_api TEXT DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + " find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + " path_to_url TEXT DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + " path_to_url_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + " unvisited_url TEXT DEFAULT '',\n"      //合并所有URL 并去除已经访问过的URL (Json格式)
            + " unvisited_url_num INTEGER DEFAULT -1,\n"   //合并所有URL 并去除已经访问过的URL的数量

            + " basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";

    /**
     * 插入第一次分析完毕的 URL和PATH结果, 此时不包含动态生成的URL
     * @param msgInfo
     * @param analyseInfo
     * @return
     */
    public static synchronized int insertBasicAnalyseResult(HttpMsgInfo msgInfo, AnalyseResultModel analyseInfo){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName WHERE msg_hash = ?"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getMsgHash());
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = ("INSERT INTO tableName (" +
                        "msg_hash, req_url, req_host_port, find_url, find_url_num, find_path, find_path_num, " +
                        "find_info, find_info_num, find_api, find_api_num, unvisited_url, unvisited_url_num, run_status) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                        .replace("tableName", tableName) ;
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getMsgHash());
                    insertStmt.setString(2, msgInfo.getReqUrl());
                    insertStmt.setString(3, msgInfo.getUrlInfo().getReqHostPort());

                    insertStmt.setString(4, CastUtils.toJson(analyseInfo.getUrlList()));
                    insertStmt.setInt(5, analyseInfo.getUrlList().size());

                    insertStmt.setString(6, CastUtils.toJson(analyseInfo.getPathList()));
                    insertStmt.setInt(7, analyseInfo.getPathList().size());

                    insertStmt.setString(8, CastUtils.toJson(analyseInfo.getInfoList()));
                    insertStmt.setInt(9, analyseInfo.getInfoList().size());

                    insertStmt.setString(10, CastUtils.toJson(analyseInfo.getApiList()));
                    insertStmt.setInt(11, analyseInfo.getApiList().size());

                    insertStmt.setString(12, CastUtils.toJson(analyseInfo.getUnvisitedUrl()));
                    insertStmt.setInt(13, analyseInfo.getUnvisitedUrl().size());

                    //在这个响应中没有找到 PATH 数据,就修改状态为无需解析
                    if (analyseInfo.getPathList().size() > 0){
                        insertStmt.setString(14, Constants.ANALYSE_WAIT);
                    } else {
                        insertStmt.setString(14, Constants.ANALYSE_SKIP);
                    }

                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
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
     * 获取 指定 msgHash 对应的 所有 分析结果 数据, 用于填充 UI 表的下方 tab 数据
     * @param msgHash
     * @return
     */
    public static synchronized TableTabDataModel fetchAnalyseResultByMsgHash(String msgHash){
        TableTabDataModel tabDataModel = null;

        String selectSQL = ("SELECT * FROM tableName WHERE msg_hash = ?;")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, msgHash);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    tabDataModel = new TableTabDataModel(
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
     * 获取一条 存在 Path 并且没有 动态计算过的 path数据
     * @return
     */
    public static synchronized FindPathModel fetchUnhandledPathData(){
        FindPathModel findPathModel = null;

        // 首先选取一条记录的ID path数量大于0 并且 状态为等待分析
        String selectSQL = ("SELECT * FROM tableName WHERE find_path_num > 0 and run_status = 'ANALYSE_WAIT' LIMIT 1;")
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        //更新状态
        String updateSQL = "UPDATE tableName SET run_status = 'ANALYSE_ING' WHERE id = ?;"
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    findPathModel =  new FindPathModel(
                            rs.getInt("id"),
                            rs.getString("req_url"),
                            rs.getString("req_host_port"),
                            rs.getString("find_path")
                    );

                    //更新索引对应的数据
                    try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                        updateStatement.setInt(1, rs.getInt("id"));
                        updateStatement.executeUpdate();
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Path Data: %s", e.getMessage()));
        }
        return findPathModel;
    }


    /**
     * 获取对应ID的动态 URL （当前是动态Path计算URL、未访问URL）
     * @param id
     * @return
     */
    public static synchronized DynamicUrlsModel fetchDynamicUrlsDataById(int id){
        DynamicUrlsModel dynamicUrlsModel = null;

        String selectSQL = "SELECT id,path_to_url,unvisited_url,basic_path_num FROM tableName WHERE id = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    dynamicUrlsModel = new DynamicUrlsModel(
                            rs.getInt("id"),
                            rs.getInt("basic_path_num"),
                            rs.getString("path_to_url"),
                            rs.getString("unvisited_url")
                            );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch path_to_url and unvisited_url By Id: %s", e.getMessage()));
        }
        return dynamicUrlsModel;
    }

    /**
     * 基于ID更新 PathToUrl 的基础计数数据
     * @param id
     * @param basicPathNum
     * @return
     */
    public static synchronized int updateDynamicUrlsBasicNumById(int id, int basicPathNum){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE tableName SET basic_path_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {

            updateStatement.setInt(1, basicPathNum);
            updateStatement.setInt(2, id);

            int affectedRows = updateStatement.executeUpdate();
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
    public static synchronized int updateDynamicUrlsModel(DynamicUrlsModel dynamicUrlModel){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = ("UPDATE tableName SET " +
                "path_to_url = ?, path_to_url_num = ?, " +
                "unvisited_url = ?, unvisited_url_num = ?, " +
                "basic_path_num = ? WHERE id = ?;")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {

            updateStatement.setString(1, CastUtils.toJson(dynamicUrlModel.getPathToUrls()));
            updateStatement.setInt(2, dynamicUrlModel.getPathToUrls().size());

            updateStatement.setString(3, CastUtils.toJson(dynamicUrlModel.getUnvisitedUrls()));
            updateStatement.setInt(4, dynamicUrlModel.getUnvisitedUrls().size());

            updateStatement.setInt(5, dynamicUrlModel.getBasicPathNum());
            updateStatement.setInt(6, dynamicUrlModel.getId());

            int affectedRows = updateStatement.executeUpdate();
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

        String selectSQL = ("SELECT id, unvisited_url FROM tableName WHERE unvisited_url_num > 0 ORDER BY id ASC;")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    UnVisitedUrlsModel jsonObj = new UnVisitedUrlsModel(
                            rs.getInt("id"),
                            rs.getString("unvisited_url")
                    );
                    list.add(jsonObj);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch All UnVisited Urls: %s", e.getMessage()));
        }
        return list;
    }

    /**
     * 实现 基于 ID 更新 unvisitedUrls
     * @param unVisitedUrlsModel
     * @return
     */
    public static synchronized int updateUnVisitedUrlsById(UnVisitedUrlsModel unVisitedUrlsModel) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE tableName SET unvisited_url = ?, unvisited_url_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
            updateStatement.setString(1, CastUtils.toJson(unVisitedUrlsModel.getUnvisitedUrls()));
            updateStatement.setInt(2, unVisitedUrlsModel.getUnvisitedUrls().size());
            updateStatement.setInt(3, unVisitedUrlsModel.getId());
            int affectedRows = updateStatement.executeUpdate();
            if (affectedRows > 0) {
                generatedId = unVisitedUrlsModel.getId();
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update unvisited Urls: %s", e.getMessage()));
        }
        return generatedId;
    }



}
