package database;

import model.HttpMsgInfo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class ReqDataTable {
    //数据表名称
    public static String tableName = "REQ_DATA";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS "+ tableName +" ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "msg_hash TEXT UNIQUE,"  //作为实际的消息独立标记
            + "req_url TEXT NOT NULL,"
            + "req_method TEXT NOT NULL,"

            + "resp_status_code INTEGER NOT NULL,"
            + "resp_length INTEGER NOT NULL," //响应长度

            + "msg_data_index INTEGER NOT NULL,"
            + "req_source TEXT NOT NULL,"   //请求来源
            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'".replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)

            + ");";


    //插入请求消息到数据库
    public static synchronized int insertOrUpdateReqData(HttpMsgInfo msgInfo, int msgDataIndex, String reqSource) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String checkSql = "SELECT id FROM  "+ tableName +"  WHERE msg_hash = ? ;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, msgInfo.getMsgHash());
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，忽略操作
                //stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, msgInfo.getUrlInfo().getReqUrl(), msgInfo.getMsgHash()));
                return 0;
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO  "+ tableName +
                        " (msg_hash, req_url, req_method, resp_status_code, msg_data_index, req_source, resp_length)" +
                        " VALUES (?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, msgInfo.getMsgHash());
                    insertStmt.setString(2, msgInfo.getUrlInfo().getRawUrlUsual());
                    insertStmt.setString(3, msgInfo.getReqMethod());
                    insertStmt.setInt(4, msgInfo.getRespStatusCode());
                    insertStmt.setInt(5, msgDataIndex);
                    insertStmt.setString(6, reqSource);
                    insertStmt.setInt(7, msgInfo.getRespBytes().length);
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


    //获取一条需要处理的数据 （状态为等待解析），并且标记状态为处理中
    public static synchronized int fetchUnhandledReqDataId(boolean updateStatus) {
        // 考虑开启事务
        int msgDataIndex = -1;

        // 首先选取一条记录的 msg_data_index
        String selectSQL = "SELECT msg_data_index FROM "+ tableName +" WHERE run_status = ? LIMIT 1;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, Constants.ANALYSE_WAIT );
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int selectedMsgDataIndex = rs.getInt("msg_data_index");

                //不更新索引直接返回查询到的索引号
                if (!updateStatus)
                    return selectedMsgDataIndex;

                //更新索引对应的数据
                String updateSQL = "UPDATE "+ tableName +" SET run_status = ? WHERE msg_data_index = ?;";

                try (PreparedStatement stmt2 = conn.prepareStatement(updateSQL)) {
                    stmt2.setString(1, Constants.ANALYSE_ING);
                    stmt2.setInt(2, selectedMsgDataIndex);
                    int affectedRows = stmt2.executeUpdate();
                    if (affectedRows > 0) {
                        msgDataIndex = selectedMsgDataIndex;
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_DEBUG, String.format("[-] Error fetch And Mark Req Data Index To Analysis: %s", e.getMessage()));
        }

        return msgDataIndex;
    }

    //获取多条需要更新的ID
    public static synchronized List<Integer> fetchUnhandledReqDataIds(int limit) {
        List<Integer> msgDataIndexList = new ArrayList<>();
        String selectSQL = "SELECT msg_data_index FROM " + tableName + " WHERE run_status = ? ORDER BY msg_data_index ASC LIMIT ?;";
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, Constants.ANALYSE_WAIT);
            stmt.setInt(2, limit); // Set the limit parameter
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                int msgDataIndex = rs.getInt("msg_data_index");
                msgDataIndexList.add(msgDataIndex);
            }
        } catch (Exception e) {
            stderr_println(LOG_DEBUG, String.format("[-] Error fetching and marking Req Data Indices for Analysis: %s", e.getMessage()));
        }
        return msgDataIndexList;
    }

    /**
     * 更新多个id的状态
     */
    public static synchronized int updateUnhandledReqDataStatusByIds(List<Integer> msgDataIndexList) {
        int updatedCount = -1;

        String updateSQL = "UPDATE " + tableName + " SET run_status = ? WHERE msg_data_index IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgDataIndexList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, Constants.ANALYSE_ING);

            for (int i = 0; i < msgDataIndexList.size(); i++) {
                stmtUpdate.setInt(i + 2, msgDataIndexList.get(i));
            }

            updatedCount = stmtUpdate.executeUpdate();

            if (updatedCount != msgDataIndexList.size()) {
                stderr_println(LOG_DEBUG, "[!] Number of updated rows does not match number of selected rows.");
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error updating Req Data Status: %s", e.getMessage()));
        }
        return updatedCount;
    }



    /**
     * 统计所有已经识别完成的URL的数量
     * @return
     */
    public static synchronized int getReqDataCountWhereStatusIsEnd() {
        int count = 0;

        String selectSQL = "SELECT COUNT(*) FROM "+ tableName + "  WHERE run_status != ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)){
            stmt.setString(1, Constants.ANALYSE_WAIT);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                count = rs.getInt(1); // 获取第一列的值，即 COUNT(*) 的结果
            }
        } catch (Exception e) {
            stderr_println(String.format("Counts Table [%s] Error: %s",tableName, e.getMessage() ));
        }
        return count;
    }


    //获取没有数据的行,备用,用于后续删除数据
    public static synchronized int deleteReqDataById(int id) {
        int rowsAffected = -1;

        // 获取当前所有记录的数据
        String deleteSQL = "DELETE FROM  "+ tableName +" WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            stmt.setInt(1, id);
            rowsAffected = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(String.format("[-] Error delete Data By Id On Table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return rowsAffected;
    }

}
