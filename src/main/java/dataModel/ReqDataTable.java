package dataModel;

import model.HttpMsgInfo;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import static utils.BurpPrintUtils.*;

public class ReqDataTable {
    //数据表名称
    static String tableName = "req_data";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "msg_id TEXT NOT NULL,\n"
            + "msg_hash TEXT NOT NULL,\n"
            + "req_url TEXT NOT NULL,\n"
            + "req_proto TEXT NOT NULL,\n"
            + "req_host TEXT NOT NULL, \n"
            + "req_port INTEGER NOT NULL,\n"
            + "req_method TEXT NOT NULL,\n"
            + "resp_status TEXT NOT NULL,\n"
            + "msg_data_index INTEGER NOT NULL,\n"
            + "run_status TEXT NOT NULL,\n"
            + "req_source TEXT NOT NULL\n" //请求来源
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateReqData(HttpMsgInfo msgInfo, int msgId, int msgDataIndex, String reqSource) {
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
                stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = ("INSERT INTO tableName (" +
                        "msg_id, msg_hash, req_url, req_proto, req_host, req_port, " +
                        "req_method, resp_status, msg_data_index, run_status, req_source) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                        .replace("tableName", tableName);
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
                    insertStmt.setString(10, Constants.ANALYSE_WAIT);
                    insertStmt.setString(11, reqSource);
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


    //获取一条需要处理的数据，并且标记为处理中
    public static synchronized int fetchAndMarkReqData(boolean updataStatus) {
        // 考虑开启事务
        int msgDataIndex = -1;

        // 首先选取一条记录的 msg_data_index
        String selectSQL = "SELECT msg_data_index FROM tableName WHERE run_status = 'ANALYSE_WAIT' LIMIT 1;"
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        String updateSQL = "UPDATE tableName SET run_status = 'ANALYSE_ING' WHERE msg_data_index = ?;"
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("tableName", tableName);

        DBService dbService = DBService.getInstance();
        try (Connection conn = dbService.getNewConnection(); PreparedStatement selectStatement = conn.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next()) {
                int selectedMsgDataIndex = rs.getInt("msg_data_index");

                //不更新索引直接返回查询到的索引号
                if (!updataStatus)
                    return selectedMsgDataIndex;

                //更新索引对应的数据
                try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                    updateStatement.setInt(1, selectedMsgDataIndex);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        msgDataIndex = selectedMsgDataIndex;
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch And Mark Req Data To Analysis: %s", e.getMessage()));
            e.printStackTrace();
        }

        return msgDataIndex;
    }
}
