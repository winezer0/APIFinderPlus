package dataModel;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import utils.HttpMsgInfo;

import java.io.PrintWriter;
import java.sql.*;

public class ListenUrlsTable {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    //数据表名称
    static String tableName = "listen_urls";

    //创建用于存储所有 访问成功的 URL的数据库 listen_urls
    static String listenUrlsSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + " req_proto TEXT NOT NULL,\n"
            + " req_host TEXT NOT NULL,\n"
            + " req_port TEXT NOT NULL,\n"
            + " req_path_dir TEXT NOT NULL,\n"
            + " resp_status TEXT\n"
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdateListenUrl(HttpMsgInfo msgInfo) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName "
                .replace("tableName", tableName)
                + "WHERE req_proto = ? "
                + "AND req_host = ? "
                + "AND req_port = ? "
                + "AND req_path_dir = ? "
                + "AND resp_status = ?";

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            setStmt(checkStmt, msgInfo);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String updateSql = "UPDATE tableName ".replace("tableName", tableName) +
                        "SET req_proto = ?, " +
                        "req_host = ?, " +
                        "req_port = ?, " +
                        "req_path_dir = ?, " +
                        "resp_status = ? " +
                        "WHERE id = ?" ;

                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    setStmt(updateStmt, msgInfo);
                    updateStmt.setInt(6, generatedId);
                    updateStmt.executeUpdate();
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName ".replace("tableName", tableName) +
                        "(req_proto, req_host, req_port, req_path_dir,resp_status) VALUES (?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    setStmt(insertStmt, msgInfo);
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

    private static void setStmt(PreparedStatement stmt, HttpMsgInfo msgInfo) throws SQLException {
        stmt.setString(1, msgInfo.getReqProto());
        stmt.setString(2, msgInfo.getReqHost());
        stmt.setInt(3, msgInfo.getReqPort());
        stmt.setString(4, msgInfo.getReqPathDir());
        stmt.setString(5, msgInfo.getRespStatus());
    }


}
