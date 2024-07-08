package database;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.TableTabDataModel;
import model.FindPathModel;
import model.HttpMsgInfo;

import static utils.BurpPrintUtils.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static burp.InfoAnalyse.*;

public class InfoAnalyseTable {
    //数据表名称
    static String tableName = "INFO_ANALYSE";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"  //请求Hash信息
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

            + " smart_api TEXT DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + " smart_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + " unvisited_url TEXT DEFAULT '',\n"      //合并所有URL 并去除已经访问过的URL (Json格式)
            + " unvisited_url_num INTEGER DEFAULT -1,\n"   //合并所有URL 并去除已经访问过的URL的数量

            + " basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";

    //插入分析完整的 基本 敏感信息 和 URI数据
    public static synchronized int insertBaseAnalyseData(HttpMsgInfo msgInfo, JSONObject analyseInfo){
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
                        "msg_hash, req_url, req_host_port, find_url, find_url_num, find_path, find_path_num, find_info, find_info_num, find_api, find_api_num, run_status) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                        .replace("tableName", tableName) ;
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getMsgHash());
                    insertStmt.setString(2, msgInfo.getReqUrl());
                    insertStmt.setString(3, msgInfo.getUrlInfo().getReqHostPort());

                    insertStmt.setString(4, analyseInfo.getJSONArray(URL_KEY).toJSONString());
                    insertStmt.setInt(5, analyseInfo.getJSONArray(URL_KEY).size());

                    insertStmt.setString(6, analyseInfo.getJSONArray(PATH_KEY).toJSONString());
                    insertStmt.setInt(7, analyseInfo.getJSONArray(PATH_KEY).size());

                    insertStmt.setString(8, analyseInfo.getJSONArray(INFO_KEY).toJSONString());
                    insertStmt.setInt(9, analyseInfo.getJSONArray(INFO_KEY).size());

                    insertStmt.setString(10, analyseInfo.getJSONArray(API_KEY).toJSONString());
                    insertStmt.setInt(11, analyseInfo.getJSONArray(API_KEY).size());

                    //在这个响应中没有找到API数据,就修改状态为无需解析
                    if (analyseInfo.getJSONArray(API_KEY).size() > 0){
                        insertStmt.setString(12, Constants.ANALYSE_WAIT);
                    } else {
                        insertStmt.setString(12, Constants.ANALYSE_SKIP);
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

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    //获取一条需要分析的Path数据
    public static synchronized FindPathModel fetchUnhandledSmartApiData(){
        FindPathModel findPathModel = null;

        // 首先选取一条记录的ID
        String selectSQL = ("SELECT id,req_url,req_host_port,find_path FROM tableName " +
                "WHERE find_path_num > 0 and run_status = 'ANALYSE_WAIT' LIMIT 1;")
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

    //插入分析完整的smart api 数据
    public static synchronized int insertAnalyseSmartApiData(int dataId, JSONObject analyseApiInfo){
        int dataIndex = -1; // 默认ID值，如果没有生成ID，则保持此值

        // todo: 实现插入 unvisited_url 数据
        String updateSQL = "UPDATE tableName SET smart_api = ?, smart_api_num = ?, basic_path_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        int basicPathNum = (int) analyseApiInfo.get(Constants.BASIC_PATH_NUM);
        JSONArray findUrls = (JSONArray) analyseApiInfo.get(Constants.FIND_PATH);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
            updateStatement.setString(1, findUrls.toJSONString());
            updateStatement.setInt(2, findUrls.size());
            updateStatement.setInt(3, basicPathNum);
            updateStatement.setInt(4, dataId);
            int affectedRows = updateStatement.executeUpdate();
            if (affectedRows > 0) {
                dataIndex = dataId;
            }

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update Path Data: %s", e.getMessage()));
        }

        return dataIndex; // 返回ID值，无论是更新还是插入
    }

    //获取一条需要分析的数据的ID,判断是否有需要分析的数据
    public static synchronized int fetchUnhandledSmartApiDataId(){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        // 首先选取一条记录的ID
        String selectSQL = "SELECT id FROM tableName WHERE find_path_num > 0 and run_status = 'ANALYSE_WAIT' LIMIT 1;"
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    generatedId = rs.getInt("id");
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Smart Api Data: %s", e.getMessage()));
        }
        return generatedId;
    }


    //获取指定msgHash的数据
    public static synchronized TableTabDataModel fetchAnalyseResultByMsgHash(String msgHash){
        TableTabDataModel tabDataModel = null;

        String selectSQL = ("SELECT msg_hash,find_url,find_path,find_info,find_api,smart_api,unvisited_url " +
                "FROM tableName WHERE msg_hash = ?;")
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
                            rs.getString("smart_api"),
                            rs.getString("unvisited_url")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Analyse Result Data By MsgHash: %s", e.getMessage()));
        }
        return tabDataModel;
    }
}
