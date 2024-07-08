package database;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.HttpMsgInfo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static utils.BurpPrintUtils.*;

public class RecordUrlTable {
    //数据表名称
    static String tableName = "RECORD_URL";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + " req_host_port TEXT NOT NULL,\n"
            + " req_url TEXT NOT NULL,\n"  //记录访问过的URL
            + " resp_status_code TEXT NOT NULL\n" //记录访问过的URL状态
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateAccessedUrl(HttpMsgInfo msgInfo) {
        String reqUrl = msgInfo.getReqUrl();
        String reqHostPort = msgInfo.getUrlInfo().getReqHostPort();
        int respStatusCode = msgInfo.getRespStatusCode();

        return insertOrUpdateAccessedUrl(reqUrl, reqHostPort, respStatusCode);
    }

    public static synchronized int insertOrUpdateAccessedUrl(String reqUrl,String reqHostPort, int respStatusCode) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName WHERE req_url = ? AND resp_status_code = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, reqUrl);
            checkStmt.setInt(2, respStatusCode);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                // stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, reqUrl, respStatusCode));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_url,req_host_port,resp_status_code) VALUES (?, ?, ?);"
                        .replace("tableName", tableName);
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, reqUrl);
                    insertStmt.setString(2, reqHostPort); //便于查找对应的URl信息
                    insertStmt.setInt(3, respStatusCode);
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
        return generatedId;
    }
}
