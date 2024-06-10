package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import model.HttpMsgInfo;

import java.io.PrintWriter;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class MsgDataTable {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //数据表名称
    static String tableName = "msg_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " msg_hash TEXT,\n"
            + " req_url TEXT NOT NULL,\n"
            + " req_bytes BLOB,\n"
            + " resp_bytes BLOB\n"
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdateMsgData(HttpMsgInfo msgInfo) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName WHERE msg_hash = ? ".replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
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
                        "(msg_hash, req_url, req_bytes, resp_bytes) VALUES (?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getMsgHash());
                    insertStmt.setString(2, msgInfo.getReqUrl());
                    insertStmt.setBytes(3, msgInfo.getReqBytes());
                    insertStmt.setBytes(4, msgInfo.getRespBytes());
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
            e.printStackTrace(stderr);
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }


    public static synchronized Map<String, Object> selectMsgDataById(Integer msgDataIndex){
        Map<String, Object> msgData = null;

        String selectMsgDataByIdSql = "SELECT * FROM tableName WHERE id = ?"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectMsgDataByIdSql)) {
            stmt.setInt(1, msgDataIndex);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    msgData = new HashMap<>();
                    msgData.put("msg_hash", rs.getString("msg_hash"));
                    msgData.put("req_url", rs.getBytes("req_url"));
                    msgData.put("req_bytes", rs.getBytes("req_bytes"));
                    msgData.put("resp_bytes", rs.getBytes("resp_bytes"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println(String.format("[-] Error Select Msg Data By Id: %s", msgDataIndex));
            e.printStackTrace(BurpExtender.getStderr());
        }
        return msgData;
    }
}
