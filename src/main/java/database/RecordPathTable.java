package database;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.HttpMsgInfo;
import java.sql.*;

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

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
            + ");";


    //插入数据库
    public static synchronized int insertOrUpdateSuccessUrl(HttpMsgInfo msgInfo) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM tableName "
                .replace("tableName", tableName)
                + "WHERE req_proto = ? "
                + "AND req_host_port = ? "
                + "AND req_path_dir = ? "
                + "AND resp_status_code = ?";

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getUrlInfo().getReqProto());
            checkStmt.setString(2, msgInfo.getUrlInfo().getReqHostPort());
            checkStmt.setString(3, msgInfo.getUrlInfo().getReqPathDir());
            checkStmt.setString(4, msgInfo.getRespStatusCode());

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getUrlInfo().getReqBaseDir(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_proto, req_host_port, req_path_dir, resp_status_code) VALUES (?, ?, ?, ?)"
                        .replace("tableName", tableName);
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getUrlInfo().getReqProto());
                    insertStmt.setString(2, msgInfo.getUrlInfo().getReqHostPort());
                    insertStmt.setString(3, msgInfo.getUrlInfo().getReqPathDir());
                    insertStmt.setString(4, msgInfo.getRespStatusCode());
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
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }


    //判断是否存在需要处理的URL
    public static synchronized int fetchUnhandledRecordUrlId(){
        // 考虑开启事务
        int dataIndex = -1;

        String selectSQL = "SELECT id FROM tableName WHERE run_status == 'ANALYSE_WAIT' LIMIT 1;"
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement selectStatement = conn.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
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
    public static synchronized JSONArray fetchUnhandledRecordUrls() {
        // 创建一个列表或集合来存储查询结果
        JSONArray jsonArray = new JSONArray();

        //1、标记需要处理的数据 更新状态为解析中
        String updateMarkSQL1 = "UPDATE tableName SET run_status = 'ANALYSE_ING' WHERE id in (SELECT id FROM tableName WHERE run_status = 'ANALYSE_WAIT');"
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)
                .replace("tableName", tableName);

        //2、获取 解析中 状态的 Host、数据、ID列表
        String selectSQL = "SELECT req_host_port, GROUP_CONCAT(req_path_dir, 'SPLIT_SYMBOL') AS req_path_dirs FROM tableName WHERE run_status == 'ANALYSE_ING' GROUP BY req_host_port;"
                .replace("SPLIT_SYMBOL", Constants.SPLIT_SYMBOL)
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("tableName", tableName);

        //3、更新 解析中 对应的状态为解析完成
        String updateMarkSQL2 = "UPDATE tableName SET run_status = 'ANALYSE_END' WHERE id in (SELECT id FROM tableName WHERE run_status = 'ANALYSE_ING');"
                .replace("ANALYSE_END", Constants.ANALYSE_END)
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement updateMarkSQL1Stmt = conn.prepareStatement(updateMarkSQL1);){
            int affectedRows = updateMarkSQL1Stmt.executeUpdate();
            if (affectedRows > 0) {
                //存在需要更新的数据
                try (PreparedStatement selectStatement = conn.prepareStatement(selectSQL)){
                    //获取查询数据
                    ResultSet rs = selectStatement.executeQuery();

                    while (rs.next()) {
                        // 从结果集中获取每一列的值 将数据存储到Map中
                        JSONObject jsonObject = new JSONObject();
                        jsonObject.put(Constants.REQ_HOST_PORT, rs.getString("req_host_port"));
                        jsonObject.put(Constants.REQ_PATH_DIRS, rs.getString("req_path_dirs"));
                        jsonArray.add(jsonObject);
                    }

                    //更新查询状态
                    try (PreparedStatement updateMarkSQL2Stmt = conn.prepareStatement(updateMarkSQL2)){
                        updateMarkSQL2Stmt.executeUpdate();
                    }
                }
            }

        } catch (Exception e) {
            stderr_println(String.format("[-] Error fetch And Mark Url Record Data To Analysis: %s", e.getMessage()));
            e.printStackTrace();
        }

        return jsonArray;
    }
}
