package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;

public class CommonSql {
    /**
     * 存储通用的SQL查询类
     */

    /**
     * 根据运行状态取获取对应 ID list
     */
    public static synchronized List<Integer> fetchIdsByRunStatus(String tableName, int limit, String analyseStatus) {
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
            stderr_println(LOG_DEBUG, String.format("[-] Error fetching [%s] ids: %s", tableName, e.getMessage()));
        }
        return ids;
    }

    /**
     * 更新多个 ID列表 的状态
     */
    public static synchronized int updateStatusByIds(String tableName, List<Integer> ids, String updateStatus) {
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
            stderr_println(LOG_ERROR, String.format("[-] Error updating [%s] Data Status: %s", tableName, e.getMessage()));
        }
        return updatedCount;
    }

    /**
     * 根据运行状态取获取对应请求 msghash list
     * @return
     */
    public static synchronized List<String> fetchMsgHashByRunStatus(String tableName, int limit, String analyseStatus) {
        List<String> msgHashList = new ArrayList<>();
        String selectSQL = "SELECT msg_hash FROM " + tableName + " WHERE run_status = ? ORDER BY id ASC LIMIT ?;";
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, analyseStatus);
            stmt.setInt(2, limit); // Set the limit parameter
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String msgHash = rs.getString("msg_hash");
                msgHashList.add(msgHash);
            }
        } catch (Exception e) {
            stderr_println(LOG_DEBUG, String.format("[-] Error fetching [%s] MsgHash List from Analysis: %s",tableName, e.getMessage()));
        }
        return msgHashList;
    }

    /**
     * 更新多个 msgHash 的状态
     */
    public static synchronized int updateStatusByMsgHashList(String tableName, List<String> msgHashList, String updateStatus) {
        int updatedCount = -1;

        String updateSQL = "UPDATE " + tableName + " SET run_status = ? WHERE msg_hash IN $buildInParamList$;"
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
     * 基于 host 列表 同时删除多行
     */
    public static synchronized int deleteDataByRootUrls(List<String> rootUrls, String tableName) {
        if (isEmptyObj(rootUrls)) return 0;

        // 构建SQL语句，使用占位符 ? 来代表每个ID
        String deleteSQL = "DELETE FROM "+ tableName +"  WHERE root_url IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(rootUrls.size()));

        return runDeleteSql(deleteSQL, rootUrls, tableName);
    }

//    /**
//     * 基于 URL 列表 同时删除多行 复用 deleteDataByHosts
//     */
//    public static synchronized int deleteDataByUrlToRootUrls(List<String> urlList, String tableName) {
//        //获取所有URL的HOST列表
//        Set<String> set = new HashSet<>();
//        for (String url: urlList){
//            set.add(new HttpUrlInfo(url).getRootUrlUsual());
//        }
//        ArrayList<String> rootUrls = new ArrayList<>(set);
//
//        if (isEmptyObj(rootUrls)) return 0;
//        return deleteDataByRootUrls(rootUrls, tableName);
//    }

//    /**
//     * 基于 msgHash 列表 同时删除多个 行
//     */
//    public static synchronized int deleteDataByMsgHashList(List<String> msgHashList, String tableName) {
//        if (isEmptyObj(msgHashList)) return 0;
//
//        // 构建SQL语句，使用占位符 ? 来代表每个ID
//        String deleteSQL = "DELETE FROM "+ tableName + "  WHERE msg_hash IN $buildInParamList$;"
//                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));
//
//        return runDeleteSql(deleteSQL, msgHashList, tableName);
//    }

    /**
     * 执行删除数据行的SQL语句
     */
    private static int runDeleteSql(String deleteSQL, List<String> stringList, String tableName) {
        int totalRowsAffected = 0;
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            // 设置SQL语句中的参数值 i+1表示从第一个?号开始设置
            for (int i = 0; i < stringList.size(); i++) {
                stmt.setString(i + 1, stringList.get(i));
            }
            // 执行删除操作
            totalRowsAffected = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(String.format("[-] Error deleting [%s] Data By deleteSQL: %s", tableName, e.getMessage()));
            e.printStackTrace();
        }
        return totalRowsAffected;
    }

    /**
     * 基于 id 列表 同时删除多个 行
     */
    public static synchronized int deleteDataByIds(List<Integer> ids, String tableName) {
        int totalRowsAffected = 0;

        if (ids.isEmpty()) return totalRowsAffected;

        // 构建SQL语句，使用占位符 ? 来代表每个ID
        String deleteSQL = "DELETE FROM "+ tableName + "  WHERE id IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(ids.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            // 设置SQL语句中的参数值 i+1表示从第一个?号开始设置
            for (int i = 0; i < ids.size(); i++) {
                stmt.setInt(i + 1, ids.get(i));
            }
            // 执行删除操作
            totalRowsAffected = stmt.executeUpdate();

        } catch (Exception e) {
            stderr_println(String.format("[-] Error deleting Data By Ids On Table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return totalRowsAffected;
    }

    /**
     * 统计数据表行数大小
     */
    public static synchronized int getTableCounts(String tableName) {
        int count = 0;

        String selectSQL = "SELECT COUNT(*) FROM  "+ tableName +" ;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL);
             ResultSet rs = stmt.executeQuery()) {

            if (rs.next()) {
                count = rs.getInt(1); // 获取第一列的值，即 COUNT(*) 的结果
            }
        } catch (Exception e) {
            stderr_println(String.format("Error Counts [%s]: %s",tableName, e.getMessage() ));
        }
        return count;
    }

    /**
     * 获取任意表的任意列的字符串拼接
     */
    public static synchronized String fetchConcatColumnToString(String tableName, String columnName) {
        String concatenatedURLs = null;

        String concatSQL = "SELECT GROUP_CONCAT($columnName$,',') AS concatenated_urls FROM "+ tableName +";"
                .replace("$columnName$",columnName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(concatSQL)) {
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                concatenatedURLs = rs.getString("concatenated_urls");
            }

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetching [%s] concatenating [%s]: %s",tableName, columnName, e.getMessage()));
            e.printStackTrace();
        }
        return concatenatedURLs;
    }

//    /**
//     * 基于 url前缀 列表 删除行
//     */
//    public static synchronized int deleteDataByLikeRootUrl(String rootUrl, String tableName) {
//        if (isEmptyObj(rootUrl)) return 0;
//
//        int totalRowsAffected = 0;
//
//        // 构建SQL语句，使用占位符 ? 来代表每个ID
//        String deleteSQL = "DELETE FROM "+ tableName + "  WHERE req_url like ?;";
//
//        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
//            // 执行删除操作
//            stmt.setString(1, rootUrl+"%");
//            totalRowsAffected= stmt.executeUpdate();
//        } catch (Exception e) {
//            stderr_println(String.format("[-] Error deleting [%s] Data By Starts With rootUrl: %s", tableName, e.getMessage()));
//            e.printStackTrace();
//        }
//        return totalRowsAffected;
//    }

    /**
     * 基于 多个url前缀 列表 删除行
     */
    public static synchronized int batchDeleteDataByLikeRootUrls(List<String> rootUrlList, String tableName) {
        if (isEmptyObj(rootUrlList)) return 0;

        int totalRowsAffected = 0;
        String deleteSQL = "DELETE FROM "+ tableName + " WHERE req_url LIKE ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            // 开启批处理
            conn.setAutoCommit(false);
            // 遍历rootUrlList，为每个rootUrl准备并添加到批处理队列
            for (String rootUrl : rootUrlList) {
                stmt.setString(1, rootUrl + "%");
                stmt.addBatch();
            }
            // 执行批处理
            int[] rowsAffected = stmt.executeBatch();
            conn.commit();
            // 计算受影响的总行数
            for (int row : rowsAffected) {
                totalRowsAffected += row;
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error deleting [%s] Data By Starts With rootUrl List: %s", tableName, e.getMessage()));
        }
        return totalRowsAffected;
    }
}
