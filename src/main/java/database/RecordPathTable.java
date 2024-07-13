package database;

import model.HttpMsgInfo;
import model.HttpUrlInfo;
import model.RecordPathDirsModel;
import model.RecordPathModel;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class RecordPathTable {
    //数据表名称
    public static String tableName = "RECORD_PATH";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + "req_hash TEXT UNIQUE, \n"  // 添加一列 req_hash 作为 req_proto req_host_port req_path_dir resp_status_code 的 特征值
            + "req_proto TEXT NOT NULL,\n"
            + "req_host_port TEXT NOT NULL,\n"
            + "req_path_dir TEXT NOT NULL,\n"
            + "resp_status_code TEXT NOT NULL, \n"
            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'"
            .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";


    //插入一条路径记录
    public static synchronized int insertOrUpdateSuccessUrlPath(RecordPathModel recordPathModel) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String selectSql = ("SELECT id FROM tableName WHERE req_hash = ?;")
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSql))
        {
            // 检查记录是否存在
            stmt.setString(1, recordPathModel.getReqHash());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                // stdout_println(LOG_DEBUG, String.format("[*] Ignore Update %s ->  %s %s %s %s", tableName, reqProto, reqHostPort, reqPathDir, respStatusCode));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_proto, req_host_port, req_path_dir, resp_status_code, req_hash) VALUES (?, ?, ?, ?, ?);"
                        .replace("tableName", tableName);
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, recordPathModel.getReqProto());
                    insertStmt.setString(2, recordPathModel.getReqHostPort());
                    insertStmt.setString(3, recordPathModel.getReqPathDir());
                    insertStmt.setInt(4, recordPathModel.getRespStatusCode());
                    insertStmt.setString(5, recordPathModel.getReqHash());
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
            stderr_println(String.format("[-] Error inserting or updating table -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }


    //插入一条路径记录 复用
    public static synchronized int insertOrUpdateSuccessUrlPath(HttpMsgInfo msgInfo) {
        RecordPathModel recordPathModel = new RecordPathModel(msgInfo.getUrlInfo(), msgInfo.getRespStatusCode());
        return insertOrUpdateSuccessUrlPath(recordPathModel);
    }

    //插入一条路径记录 复用
    public static synchronized int insertOrUpdateSuccessUrlPath(String reqUrl, int respStatusCode) {
        RecordPathModel recordPathModel = new RecordPathModel(new HttpUrlInfo(reqUrl), respStatusCode );
        return insertOrUpdateSuccessUrlPath(recordPathModel);
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
    public static synchronized List<RecordPathDirsModel> fetchAllNotAddToTreeRecords() {
        // 创建一个列表或集合来存储查询结果
        List<RecordPathDirsModel> recordPathModels = new ArrayList<>();

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
                        RecordPathDirsModel recordPathDirsModel = new RecordPathDirsModel(
                                rs.getString("req_proto"),
                                rs.getString("req_host_port"),
                                rs.getString("req_path_dirs")
                        );

                        recordPathModels.add(recordPathDirsModel);
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


    public static int[] batchInsertOrUpdateSuccessUrl(List<RecordPathModel> recordPathModels) {
        int[] generatedIds = null;

        String insertSql = ("INSERT INTO tableName (req_proto, req_host_port, req_path_dir, resp_status_code, req_hash) VALUES (?, ?, ?, ?, ?) " +
                "ON CONFLICT(req_hash) DO NOTHING")
                .replace("tableName", tableName);

        //ON CONFLICT(req_proto, req_host_port, req_path_dir, resp_status_code) DO NOTHING
        // 这个语句的作用是在尝试向表中插入一条记录时，如果发现有与之冲突的唯一约束
        // （即在 req_proto, req_host_port, req_path_dir, resp_status_code 这些字段上已经存在相同的值组合），
        // 那么数据库将不会执行任何操作，也不会抛出错误，而是简单地跳过这条记录的插入。
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
            conn.setAutoCommit(false); // 开启事务处理
            for (RecordPathModel record : recordPathModels) {
                insertStmt.setString(1, record.getReqProto());
                insertStmt.setString(2, record.getReqHostPort());
                insertStmt.setString(3, record.getReqPathDir());
                insertStmt.setInt(4, record.getRespStatusCode());
                insertStmt.setString(5, record.getReqHash());
                insertStmt.addBatch(); // 添加到批处理
                }
                generatedIds = insertStmt.executeBatch();
                conn.commit(); // 提交事务
        } catch (Exception e) {
            stderr_println(String.format("[-] Error executing batch insert/update table [%s] : [%s]",tableName, e.getMessage()));
            e.printStackTrace();
        }
        return generatedIds;
    }

    //简单复用 实现批量插入
    public static int[] batchInsertOrUpdateSuccessUrl(List<String> findUrls, int respStatusCode) {
        List<RecordPathModel> recordPathModels = new ArrayList<>();

        for (String findUrl: findUrls){
            HttpUrlInfo urlInfo = new HttpUrlInfo(findUrl);
            RecordPathModel recordPathModel = new RecordPathModel(
                    urlInfo.getProto(),
                    urlInfo.getHostPort(),
                    urlInfo.getPathDir(),
                    respStatusCode
            );
            recordPathModels.add(recordPathModel);
        }

        return batchInsertOrUpdateSuccessUrl(recordPathModels);
    }


}
