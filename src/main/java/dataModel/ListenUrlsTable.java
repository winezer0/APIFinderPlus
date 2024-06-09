package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class ListenUrlsTable {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //插入数据库
    public synchronized int insertOrUpdateListenUrl(String msgHash, String reqUrl, byte[] request, byte[] response) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM requests_response WHERE msg_hash = ?";

        DBService dbService = DBService.getInstance();
        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, reqUrl);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String updateSql = "UPDATE requests_response SET request = ?, response = ? WHERE id = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setBytes(1, request);
                    updateStmt.setBytes(2, response);
                    updateStmt.setInt(3, generatedId);
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
