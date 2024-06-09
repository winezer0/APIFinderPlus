package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import utils.HttpMsgInfo;

import java.io.PrintWriter;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class ListenUrlsTable {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //数据表名称
    static String tableName = "listen_urls";

    //创建用于存储所有 访问成功的 URL的数据库 listen_urls
    static String listenUrlsSQL = "CREATE TABLE IF NOT EXISTS listen_urls (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + " req_host TEXT NOT NULL,\n"      // 请求 host
            + " req_path_dir TEXT NOT NULL,\n"  // 请求 path
            + " resp_status TEXT,\n"            // 响应 状态码
            + " resp_length TEXT\n"             // 响应 长度
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdateListenUrl(HttpMsgInfo msgInfo) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM listen_urls WHERE req_host = ? AND req_path_dir = ?";

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getMsgHash());
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String updateSql = "UPDATE listen_urls SET " +
                        "msg_hash = ?, " +
                        "req_url = ?, " +
                        "req_host = ?, " +
                        "req_path = ?, " +
                        "resp_status = ?, " +
                        "resp_length = ?, " +
                        "WHERE id = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setString(1, msgInfo.getMsgHash());
                    updateStmt.setString(2, msgInfo.getReqUrl());
                    updateStmt.setString(3, msgInfo.getReqHost());
                    updateStmt.setString(4, msgInfo.getReqPath());
                    updateStmt.setString(5, msgInfo.getRespStatus());
                    updateStmt.setInt(6, msgInfo.getRespBodyLen());
                    updateStmt.setInt(7, generatedId);
                    updateStmt.executeUpdate();
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO requests_response(url, request, response, uniqueCode) VALUES(?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, reqUrl);
                    insertStmt.setBytes(2, request);
                    insertStmt.setBytes(3, response);
                    insertStmt.setString(4, msgHash);
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
            stderr.println("[-] Error inserting or updating requests_response table: " + reqUrl);
            e.printStackTrace(stderr);
        }


        return generatedId; // 返回ID值，无论是更新还是插入
    }


}
