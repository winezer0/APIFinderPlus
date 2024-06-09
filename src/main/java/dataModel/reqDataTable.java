package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import utils.HttpMsgInfo;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class reqDataTable {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //数据表名称
    static String tableName = "req_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n".replace("tableName", tableName)
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "msg_id TEXT, \n"
            + "msg_hash TEXT,\n"
            + "req_url TEXT NOT NULL,\n"
            + "req_proto TEXT \n"
            + "req_host TEXT, \n"
            + "req_port INTEGER, \n"
            + "req_method TEXT, \n"
            + "resp_status TEXT, \n"
            + "msg_data_index INTEGER, \n"
            + "run_status TEXT\n"
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateReqData(HttpMsgInfo msgInfo, int msgId, int msgDataIndex) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName WHERE msg_hash = ?".replace("tableName", tableName);
        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getMsgHash());
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout.println(String.format("Ignore Update [%s] %s -> %s", tableName, msgInfo.getReqUrl(), msgInfo.getMsgHash()));
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName ".replace("tableName", tableName) +
                        "(msg_id, msg_hash, req_url, req_proto, req_host, req_port, req_method, resp_status, msg_data_index, run_status) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setInt(1, msgId);
                    insertStmt.setString(2, msgInfo.getMsgHash());
                    insertStmt.setString(3, msgInfo.getReqUrl());
                    insertStmt.setString(4, msgInfo.getReqProto());
                    insertStmt.setString(5, msgInfo.getReqHost());
                    insertStmt.setInt(6, msgInfo.getReqPort());
                    insertStmt.setString(7, msgInfo.getReqMethod());
                    insertStmt.setString(8, msgInfo.getRespStatus());
                    insertStmt.setInt(9, msgDataIndex);
                    insertStmt.setString(10, "等待解析");
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
}
