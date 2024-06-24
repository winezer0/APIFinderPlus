package dataModel;

import model.HttpMsgInfo;
import java.sql.*;

import static utils.BurpPrintUtils.*;

public class RecordUrlsTable {
    //数据表名称
    static String tableName = "record_paths";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id

            + " req_proto TEXT NOT NULL,\n"
            + " req_host TEXT NOT NULL,\n"
            + " req_port TEXT NOT NULL,\n"
            + " req_path_dir TEXT NOT NULL,\n"
            + " resp_status_code TEXT NOT NULL, \n"

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateSuccessUrl(HttpMsgInfo msgInfo) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName "
                .replace("tableName", tableName)
                + "WHERE req_proto = ? "
                + "AND req_host = ? "
                + "AND req_port = ? "
                + "AND req_path_dir = ? "
                + "AND resp_status_code = ?";

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getReqProto());
            checkStmt.setString(2, msgInfo.getReqHost());
            checkStmt.setInt(3, msgInfo.getReqPort());
            checkStmt.setString(4, msgInfo.getReqPathDir());
            checkStmt.setString(5, msgInfo.getRespStatusCode());

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getReqBasePath(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_proto, req_host, req_port, req_path_dir, resp_status_code) VALUES (?, ?, ?, ?, ?)"
                        .replace("tableName", tableName);
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getReqProto());
                    insertStmt.setString(2, msgInfo.getReqHost());
                    insertStmt.setInt(3, msgInfo.getReqPort());
                    insertStmt.setString(4, msgInfo.getReqPathDir());
                    insertStmt.setString(5, msgInfo.getRespStatusCode());
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
}
