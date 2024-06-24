package dataModel;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.HttpMsgInfo;

import static utils.BurpPrintUtils.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;

import static model.InfoAnalyse.*;

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

            + " basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";

    //插入数据库
    public static synchronized int insertAnalyseData(HttpMsgInfo msgInfo, JSONObject analyseInfo){
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
                        "msg_hash, req_url, req_host_port, find_url, find_url_num, find_path, find_path_num, find_info, find_info_num, find_api, find_api_num) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
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


    /**
     * 获取1条需要分析的Path数据
     * @return
     */
    public static synchronized Map<String, Object> fetchOneAnalysePathData(){
        JSONObject pathData = new JSONObject();

        // 首先选取一条记录的ID
        String selectSQL = "SELECT id,req_url,req_host_port,find_path FROM tableName WHERE find_path_num > 0 and run_status = 'ANALYSE_WAIT' LIMIT 1;"
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        //更新状态
        String updateSQL = "UPDATE tableName SET run_status = 'ANALYSE_END' WHERE id = ?;"
                .replace("ANALYSE_END", Constants.ANALYSE_END)
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    int selectedId = rs.getInt("id");
                    String reqUrl = rs.getString("req_url");
                    String reqHostPort = rs.getString("req_host_port");
                    String findPath = rs.getString("find_path");

                    pathData.put(Constants.DATA_ID, selectedId);
                    pathData.put(Constants.REQ_URL, reqUrl);
                    pathData.put(Constants.REQ_HOST_PORT, reqHostPort);
                    pathData.put(Constants.FIND_PATH, findPath);
                    
                    //更新索引对应的数据
                    try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                        updateStatement.setInt(1, selectedId);
                        updateStatement.executeUpdate();
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Path Data: %s", e.getMessage()));
        }
        return pathData;
    }

    //插入数据库
    public static synchronized int insertAnalyseApiData(int dataId, JSONObject analyseApiInfo){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE tableName SET smart_api = ?, smart_api_num = ?, basic_path_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        int pathNum = (int) analyseApiInfo.get(Constants.PATH_NUM);
        JSONArray findUrls = (JSONArray) analyseApiInfo.get(Constants.FIND_PATH);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
            updateStatement.setString(1, findUrls.toJSONString());
            updateStatement.setInt(2, findUrls.size());
            updateStatement.setInt(3, pathNum);
            updateStatement.setInt(4, dataId);
            updateStatement.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update Path Data: %s", e.getMessage()));
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

}
