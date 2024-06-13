package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import com.alibaba.fastjson2.JSONObject;
import model.HttpMsgInfo;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static burp.InfoAnalyse.*;

public class AnalyseDataTable {
    private static final PrintWriter stdout = BurpExtender.getStdout();
    private static final PrintWriter stderr = BurpExtender.getStderr();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();;

    //数据表名称
    static String tableName = "analyse_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"  //请求Hash信息
            + " req_url TEXT NOT NULL,\n"  //请求URL
            + " req_path TEXT NOT NULL,\n" //请求Path 便于补充根目录
            
            + " analysed_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + " find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + " analysed_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + " find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + " analysed_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + " find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量

            + " analysed_api DEFAULT '',\n"        //基于分析的不完整URI信息计算出来的URL (Json格式)
            + " find_api_num INTEGER DEFAULT -1\n"     //发现API的数量
            + ");";

    //插入数据库

    public static int insertAnalyseData(HttpMsgInfo msgInfo, JSONObject analyseInfo){
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName WHERE msg_hash = ?"
                .replace("tableName", tableName);

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getMsgHash());
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout.println(String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName ".replace("tableName", tableName) +
                        "(msg_hash, req_url, req_path, " +
                        "analysed_url, find_url_num, " +
                        "analysed_path, find_path_num, " +
                        "analysed_info, find_info_num, " +
                        "analysed_api, find_api_num) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
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
            stderr.println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, msgInfo.getReqUrl()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }



}
