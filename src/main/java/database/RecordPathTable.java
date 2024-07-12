package database;

import model.HttpMsgInfo;
import model.HttpUrlInfo;
import model.RecordPathModel;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class RecordPathTable {
    //数据表名称
    static String tableName = "RECORD_PATH";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id

            + " req_proto TEXT NOT NULL,\n"
            + " req_host_port TEXT NOT NULL,\n"
            + " req_path_dir TEXT NOT NULL,\n"
            + " resp_status_code TEXT NOT NULL, \n"

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'"
            .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)

            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateSuccessUrl(HttpMsgInfo msgInfo) {
        String reqProto = msgInfo.getUrlInfo().getReqProto();
        String reqHostPort = msgInfo.getUrlInfo().getReqHostPort();
        String reqPathDir = msgInfo.getUrlInfo().getReqPathDir();
        int respStatusCode = msgInfo.getRespStatusCode();
        return insertOrUpdateSuccessUrl(reqProto, reqHostPort, reqPathDir, respStatusCode);
    }

    //插入数据库
    public static synchronized int insertOrUpdateSuccessUrl(String reqUrl, int respStatusCode) {
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);
        String reqProto = urlInfo.getReqProto();
        String reqHostPort = urlInfo.getReqHostPort();
        String reqPathDir = urlInfo.getReqPathDir();
        return insertOrUpdateSuccessUrl(reqProto, reqHostPort, reqPathDir, respStatusCode);
    }

    public static synchronized int insertOrUpdateSuccessUrl(String reqProto, String reqHostPort, String reqPathDir, int respStatusCode) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String selectSql = ("SELECT id FROM tableName WHERE req_proto = ? AND req_host_port = ? AND req_path_dir = ? AND resp_status_code = ?")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            // 检查记录是否存在
            stmt.setString(1, reqProto);
            stmt.setString(2, reqHostPort);
            stmt.setString(3, reqPathDir);
            stmt.setInt(4, respStatusCode);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                // stdout_println(LOG_DEBUG, String.format("[*] Ignore Update %s ->  %s %s %s %s", tableName, reqProto, reqHostPort, reqPathDir, respStatusCode));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_proto, req_host_port, req_path_dir, resp_status_code) VALUES (?, ?, ?, ?)"
                        .replace("tableName", tableName);
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, reqProto);
                    insertStmt.setString(2, reqHostPort);
                    insertStmt.setString(3, reqPathDir);
                    insertStmt.setInt(4, respStatusCode);
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
            stderr_println(String.format("[-] Error inserting or updating table [%s] [%s %s %s %s]-> Error:[%s]", tableName, reqProto, reqHostPort, reqPathDir, respStatusCode, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    //判断是否存在需要处理的URL
    public static synchronized int fetchUnhandledRecordPathId(){
        // 考虑开启事务
        int dataIndex = -1;

        String selectSQL = "SELECT id FROM tableName WHERE run_status = ? LIMIT 1;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, Constants.ANALYSE_WAIT);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                dataIndex = rs.getInt("id");
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error Check Record Urls Status Is Wait: %s", e.getMessage()));
            e.printStackTrace();
        }

        return dataIndex;
    }

    //获取所有需要处理的URl数据，并且标记
    public static synchronized List<RecordPathModel> fetchAllNotAddToTreeRecords() {
        // 创建一个列表或集合来存储查询结果
        List<RecordPathModel> recordPathModels = new ArrayList<>();

        //1、标记需要处理的数据 更新状态为解析中
        String updateMarkSQL1 = ("UPDATE tableName SET run_status = ? WHERE id in (SELECT id FROM tableName WHERE run_status = ?);")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement Stmt1 = conn.prepareStatement(updateMarkSQL1);){
            Stmt1.setString(1, Constants.ANALYSE_ING);
            Stmt1.setString(2, Constants.ANALYSE_WAIT);

            int affectedRows = Stmt1.executeUpdate();
            if (affectedRows > 0) {
                //2、获取 解析中 状态的 Host、数据、ID列表
                String selectSQL = ("SELECT req_proto,req_host_port,GROUP_CONCAT(req_path_dir, ?) AS req_path_dirs " +
                        "FROM tableName WHERE run_status == ? GROUP BY req_proto,req_host_port;")
                        .replace("tableName", tableName);

                try (PreparedStatement stmt2 = conn.prepareStatement(selectSQL)){
                    stmt2.setString(1, Constants.SPLIT_SYMBOL);
                    stmt2.setString(2, Constants.ANALYSE_ING);

                    //获取查询数据
                    ResultSet rs = stmt2.executeQuery();
                    while (rs.next()) {
                        RecordPathModel recordPathModel = new RecordPathModel(
                                rs.getString("req_proto"),
                                rs.getString("req_host_port"),
                                rs.getString("req_path_dirs")
                        );

                        recordPathModels.add(recordPathModel);
                    }

                    //3、更新 解析中 对应的状态为解析完成
                    String updateMarkSQL2 = "UPDATE tableName SET run_status = ? WHERE id in (SELECT id FROM tableName WHERE run_status = ?);"
                            .replace("tableName", tableName);

                    try (PreparedStatement updateMarkSQL2Stmt = conn.prepareStatement(updateMarkSQL2)){
                        updateMarkSQL2Stmt.setString(1, Constants.ANALYSE_END);
                        updateMarkSQL2Stmt.setString(2, Constants.ANALYSE_ING);

                        updateMarkSQL2Stmt.executeUpdate();
                    }
                }
            }

        } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch And Mark Url Record Data To Analysis: %s", e.getMessage()));
            e.printStackTrace();
        }

        return recordPathModels;
    }

}
