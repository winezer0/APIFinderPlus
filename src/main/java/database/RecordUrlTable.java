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
        return insertOrUpdateAccessedUrl(
                msgInfo.getUrlInfo().getReqUrl(),
                msgInfo.getUrlInfo().getReqHostPort() ,
                msgInfo.getRespStatusCode());
    }


    //插入访问的URl
    public static synchronized int insertOrUpdateAccessedUrl(String reqUrl,String reqHostPort, int respStatusCode) {
        int generatedId = -1;
        String upsertSql = ("INSERT INTO tableName (req_url, req_host_port, resp_status_code) "
                + "VALUES (?, ?, ?) "
                + "ON CONFLICT(req_url) DO UPDATE SET resp_status_code = EXCLUDED.resp_status_code;")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(upsertSql, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setString(1, reqUrl);
            stmt.setString(2, reqHostPort);
            stmt.setInt(3, respStatusCode);

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    generatedId = generatedKeys.getInt(1);
                }
            }
        } catch (SQLException e) {
            System.err.println(String.format("Error insert Or Update Accessed Url On table [%s] -> Error:[%s]", tableName, e.getMessage()));
        }

        return generatedId;
    }


    //基于host获取获取所有访问过的URL
    public static synchronized List<String> fetchAllAccessedUrls(String reqHostPort) {
        List<String> uniqueURLs = new ArrayList<>();

        String selectSql = "SELECT req_url FROM tableName WHERE req_host_port = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSql)) {
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

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSql)) {
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
