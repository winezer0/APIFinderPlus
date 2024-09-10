package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class CommonUpdateStatus {
    /**
     * 更新多个 ID列表 的状态
     */
    public static synchronized int updateStatusByIds(String tableName, List<Integer> ids, String updateStatus) {
        int updatedCount = -1;

        String updateSQL = ("UPDATE " + tableName + " SET run_status = ? WHERE id IN $buildInParamList$;")
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
            stderr_println(LOG_ERROR, String.format("[-] Error updating [%s] Data Status: %s", tableName, e.getMessage()));
        }
        return updatedCount;
    }

    /**
     * 更新多个 msgHash 的状态
     */
    public static synchronized int updateStatusByMsgHashList(String tableName, List<String> msgHashList, String updateStatus) {
        int updatedCount = -1;

        String updateSQL = ("UPDATE " + tableName + " SET run_status = ? WHERE msg_hash IN $buildInParamList$;")
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, updateStatus);

            for (int i = 0; i < msgHashList.size(); i++) {
                stmtUpdate.setString(i + 2, msgHashList.get(i));
            }

            updatedCount = stmtUpdate.executeUpdate();

            if (updatedCount != msgHashList.size()) {
                stderr_println(LOG_DEBUG, "[!] Number of updated rows does not match number of selected rows.");
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error updating [%s] Data Status: %s",tableName, e.getMessage()));
        }
        return updatedCount;
    }

    /**
     * 基于 msgDataIndexList 更新 状态
     */
    public static synchronized int updateStatusByMsgDataIndexList(String tableName, List<Integer> msgDataIndexList, String updateStatus) {
        int updatedCount = -1;

        String updateSQL = ("UPDATE " + tableName + " SET run_status = ? WHERE msg_data_index IN $buildInParamList$;")
                .replace("$buildInParamList$", DBService.buildInParamList(msgDataIndexList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, updateStatus);

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
     * 当达到某个状态条件时 更新 msgHash 对应数据 的状态
     */
    public static synchronized int updateStatusWhenStatusByMsgHash(String tableName, String msgHash, String updateStatus, String whenStatus) {
        int updatedCount = -1;

        String updateSQL = "UPDATE " + tableName + " SET run_status = ? WHERE run_status = ? and msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, updateStatus);
            stmtUpdate.setString(2, whenStatus);
            stmtUpdate.setString(3, msgHash);

            updatedCount = stmtUpdate.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] updateStatusWhenStatusByMsgHash: [%s] Error->: %s",tableName, e.getMessage()));
        }
        return updatedCount;
    }

    /**
     * 当达到某个状态条件时 更新 root_url 对应数据 的状态
     */
    public static synchronized int updateStatusWhenStatusByRootUrl(String tableName, String rootUrl, String updateStatus, String whenStatus) {
        int updatedCount = -1;

        String updateSQL = "UPDATE " + tableName + " SET run_status = ? WHERE run_status = ? and root_url = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmtUpdate = conn.prepareStatement(updateSQL)) {
            stmtUpdate.setString(1, updateStatus);
            stmtUpdate.setString(2, whenStatus);
            stmtUpdate.setString(3, rootUrl);

            updatedCount = stmtUpdate.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] updateStatusWhenStatusByRootUrl: [%s] Error->: %s",tableName, e.getMessage()));
        }
        return updatedCount;
    }

}
