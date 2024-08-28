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
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS "+ tableName +" (\n"
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
    public static synchronized int insertOrUpdateRecordPath(RecordPathModel recordPathModel) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String selectSql = "SELECT id FROM "+ tableName +" WHERE req_hash = ?;";

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
                String insertSql = "INSERT INTO "+ tableName +
                        " (req_proto, req_host_port, req_path_dir, resp_status_code, req_hash)" +
                        " VALUES (?, ?, ?, ?, ?);";
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
    public static synchronized int insertOrUpdateRecordPath(HttpMsgInfo msgInfo) {
        RecordPathModel recordPathModel = new RecordPathModel(msgInfo.getUrlInfo(), msgInfo.getRespStatusCode());
        return insertOrUpdateRecordPath(recordPathModel);
    }

    //插入一条路径记录 复用
    public static synchronized int insertOrUpdateRecordPath(String reqUrl, int respStatusCode) {
        RecordPathModel recordPathModel = new RecordPathModel(new HttpUrlInfo(reqUrl), respStatusCode );
        return insertOrUpdateRecordPath(recordPathModel);
    }

    //批量插入 recordPathModels
    public static int[] batchInsertOrUpdateRecordPath(List<RecordPathModel> recordPathModels) {
        int[] generatedIds = null;

        String insertSql = "INSERT INTO "+ tableName +
                " (req_proto, req_host_port, req_path_dir, resp_status_code, req_hash)" +
                " VALUES (?, ?, ?, ?, ?)" +
                " ON CONFLICT(req_hash) DO NOTHING";

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
    public static int[] batchInsertOrUpdateRecordPath(List<String> findUrls, int respStatusCode) {
        List<RecordPathModel> recordPathModels = new ArrayList<>();
        for (String findUrl: findUrls){
            HttpUrlInfo urlInfo = new HttpUrlInfo(findUrl);
            RecordPathModel recordPathModel = new RecordPathModel(
                    urlInfo.getProto(),
                    urlInfo.getHostPort(),
                    urlInfo.getPathToDir(),
                    respStatusCode
            );
            recordPathModels.add(recordPathModel);
        }
        return batchInsertOrUpdateRecordPath(recordPathModels);
    }

    /**
     * 根据运行状态取获取对应请求ID
     */
    public static synchronized List<Integer> fetchIdsByRunStatus(int limit, String analyseStatus) {
        List<Integer> ids = new ArrayList<>();
        String selectSQL = "SELECT id FROM " + tableName + " WHERE run_status = ? ORDER BY id ASC LIMIT ?;";
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, analyseStatus);
            stmt.setInt(2, limit); // Set the limit parameter
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                int id = rs.getInt("id");
                ids.add(id);
            }
        } catch (Exception e) {
            stderr_println(LOG_DEBUG, String.format("[-] Error fetching [%s] id list from Analysis: %s", tableName, e.getMessage()));
        }
        return ids;
    }

    /**
     * 获取id为waiting的数据
     */
    public static List<Integer> fetchIdsByRunStatusIsWait(int limit) {
        return fetchIdsByRunStatus(limit, Constants.ANALYSE_WAIT);
    }

    /**
     * 更新多个 ID列表 的状态
     */
    private static synchronized int updateStatusByIds(List<Integer> ids, String updateStatus) {
        int updatedCount = -1;

        String updateSQL = "UPDATE " + tableName + " SET run_status = ? WHERE id IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(ids.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, updateStatus);

            for (int i = 0; i < ids.size(); i++) {
                stmtUpdate.setInt(i + 2, ids.get(i));
            }

            updatedCount = stmtUpdate.executeUpdate();

            if (updatedCount != ids.size()) {
                stderr_println(LOG_DEBUG, "[!] Number of updated rows does not match number of selected rows.");
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error updating [%s] Data Status: %s",tableName, e.getMessage()));
        }
        return updatedCount;
    }

    /**
     * 修改ID对应的数据状态 为 分析中
     */
    public static int updateStatusRunIngByIds(List<Integer> ids) {
        return updateStatusByIds(ids, Constants.ANALYSE_ING);
    }

    /**
     * 修改ID对应的数据状态 为 分析完成
     */
    public static int updateStatusRunEndByIds(List<Integer> ids) {
        return updateStatusByIds(ids, Constants.ANALYSE_END);
    }

    //获取 指定状态的数据 并封装为 路径模型
    public static List<RecordPathDirsModel> fetchPathRecordsByStatus(String analyseStatus) {
        // 创建一个列表或集合来存储查询结果
        List<RecordPathDirsModel> recordPathModels = new ArrayList<>();

        String selectSQL = "SELECT req_proto,req_host_port,GROUP_CONCAT(req_path_dir, ?) AS req_path_dirs " +
                "FROM "+ tableName +" WHERE run_status = ? GROUP BY req_proto,req_host_port;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL);){
            //2、获取 解析中 状态的 Host、数据、ID列表
            stmt.setString(1, Constants.SPLIT_SYMBOL);
            stmt.setString(2, analyseStatus);

            //获取查询数据
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                RecordPathDirsModel recordPathDirsModel = new RecordPathDirsModel(
                        rs.getString("req_proto"),
                        rs.getString("req_host_port"),
                        rs.getString("req_path_dirs")
                );
                recordPathModels.add(recordPathDirsModel);
            }

        } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch [%s] Data To Analysis: %s", tableName, e.getMessage()));
            e.printStackTrace();
        }
        return recordPathModels;
    }

    //获取 ANALYSE_ING 状态的数据 并封装为 路径模型
    public static List<RecordPathDirsModel> fetchStatusRunIngPathRecords() {
        return fetchPathRecordsByStatus(Constants.ANALYSE_ING);
    }



//    /**
//     * 将ID对应的数据查出来，封装为 RecordPathDirsModel 并返回列表
//     */
//    public static List<RecordPathDirsModel> fetchPathRecordsByIds(List<Integer> ids) {
//        List<RecordPathDirsModel> pathRecords = new ArrayList<>();
//
//        String selectSQL = "SELECT req_proto, req_host_port, GROUP_CONCAT(req_path_dir, ?) AS req_path_dirs " +
//                "FROM " + tableName + " WHERE id IN $buildInParamList$;"
//                .replace("$buildInParamList$", DBService.buildInParamList(ids.size()));
//
//        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
//            stmt.setString(1, Constants.SPLIT_SYMBOL);
//            for (int i = 0; i < ids.size(); i++) {
//                stmt.setInt(i + 2, ids.get(i));
//            }
//            ResultSet rs = stmt.executeQuery();
//            while (rs.next()) {
//                RecordPathDirsModel recordPathDirsModel = new RecordPathDirsModel(
//                        rs.getString("req_proto"),
//                        rs.getString("req_host_port"),
//                        rs.getString("req_path_dirs")
//                );
//                pathRecords.add(recordPathDirsModel);
//            }
//        } catch (SQLException e) {
//            stderr_println(String.format("[-] Error fetching records by IDs: %s", e.getMessage()));
//            e.printStackTrace();
//        }
//        return pathRecords;
//    }
}
