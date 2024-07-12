package database;

import model.HttpMsgInfo;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class RecordUrlTable {
    //数据表名称
    static String tableName = "RECORD_URL";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + "req_host_port TEXT NOT NULL,\n"
            + "req_url TEXT NOT NULL,\n"  //记录访问过的URL
            + "resp_status_code INTEGER,\n" //记录访问过的URL状态
            + "UNIQUE (req_url) ON CONFLICT REPLACE\n" //添加唯一性约束，并指定在冲突时用REPLACE行为
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateAccessedUrl(HttpMsgInfo msgInfo) {
        String reqUrl = msgInfo.getReqUrl();
        String reqHostPort = msgInfo.getUrlInfo().getReqHostPort();
        int respStatusCode = msgInfo.getRespStatusCode();

        return insertOrUpdateAccessedUrl(reqUrl, reqHostPort, respStatusCode);
    }


    //插入访问的URl
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


    //基于host获取获取所有访问过的URL
    public static synchronized List<String> fetchAllAccessedUrls(String reqHostPort) {
        List<String> uniqueURLs = new ArrayList<>();

        String selectSql = "SELECT req_url FROM tableName WHERE req_host_port = '?';"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            // 获取所有的URL
            stmt.setString(1, reqHostPort);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String reqUrl = rs.getString("req_url");
                uniqueURLs.add(reqUrl);
            }

    } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch All Accessed Url On table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }
        return uniqueURLs;
    }

    //获取所有访问过的URL
    public static synchronized List<String> fetchAllAccessedUrls() {
        List<String> uniqueURLs = new ArrayList<>();

        String selectSql = "SELECT req_url FROM tableName;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            // 获取所有的URL
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String reqUrl = rs.getString("req_url");
                uniqueURLs.add(reqUrl);
            }

        } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch All Accessed Url On table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }
        return uniqueURLs;
    }
}
