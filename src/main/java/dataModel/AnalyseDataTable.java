package dataModel;

import com.alibaba.fastjson2.JSONObject;
import model.HttpMsgInfo;

import static utils.BurpPrintUtils.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import static model.InfoAnalyse.*;

public class AnalyseDataTable {
    //数据表名称
    static String tableName = "analyse_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " data_id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"  //请求Hash信息
            + " req_url TEXT NOT NULL,\n"  //请求URL
            + " req_path TEXT NOT NULL,\n" //请求Path 便于补充根目录
            
            + " find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + " find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + " find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + " find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + " find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + " find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量

            + " find_api DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + " find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + " smart_api DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + " smart_api_num INTEGER DEFAULT -1,\n"     //发现API的数量
            + " smart_api_basic INTEGER DEFAULT -1\n"     //是基于多少个路径算出来的结果?
            + ");";

    //插入数据库
    public static synchronized int insertAnalyseData(HttpMsgInfo msgInfo, JSONObject analyseInfo){
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT data_id FROM tableName WHERE msg_hash = ?"
                .replace("tableName", tableName);

        try (Connection conn = dbService.getNewConnection();
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
                        "msg_hash, req_url, req_path, find_url, find_url_num, find_path, find_path_num, find_info, find_info_num, find_api, find_api_num) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                        .replace("tableName", tableName) ;
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getMsgHash());
                    insertStmt.setString(2, msgInfo.getReqUrl());
                    insertStmt.setString(3, msgInfo.getReqBasePath());

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
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, msgInfo.getReqUrl()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }


    /**
     * 获取1条需要分析的Path数据
     * @return
     */

    public static String DATA_ID = "data_id";
    public static String REQ_URL = "req_url";
    public static String FIND_PATH = "find_path";
    public static String SMART_API_BASIC = "smart_api_basic";

    public static synchronized Map<String, Object> fetchOneAnalysePathData(){
        Map<String, Object> pathData = null;

        // 首先选取一条记录的ID
        String selectSQL = "SELECT data_id,req_url,find_path,smart_api_basic FROM tableName WHERE find_path_num > 0 and smart_api_basic <= 0 LIMIT 1;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    pathData = new HashMap<>();
                    pathData.put(DATA_ID, rs.getInt("data_id"));
                    pathData.put(REQ_URL, rs.getString("req_url"));
                    pathData.put(FIND_PATH, rs.getString("find_path"));
                    pathData.put(SMART_API_BASIC, rs.getInt("smart_api_basic"));
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Path Data: %s", e.getMessage()));
        }
        return pathData;
    }
}
