package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;

import static utils.BurpPrintUtils.stderr_println;
import static utils.CastUtils.isEmptyObj;

public class CommonDeleteLine {
    /**
     * 执行删除数据行的SQL语句
     */
    private static int runDeleteByStringsSQL(String tableName, List<String> stringList, String deleteSQL) {
        int totalRowsAffected = 0;
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            // 设置SQL语句中的参数值 i+1表示从第一个?号开始设置
            for (int i = 0; i < stringList.size(); i++) {
                stmt.setString(i + 1, stringList.get(i));
            }
            // 执行删除操作
            totalRowsAffected = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(String.format("[-] runDeleteSql: [%s] -> Error: %s", tableName, e.getMessage()));
            e.printStackTrace();
        }
        return totalRowsAffected;
    }

    //基于 rootUrls 列表 同时删除多行
    public static synchronized int deleteLineByRootUrls(String tableName, List<String> rootUrls) {
        if (isEmptyObj(rootUrls)) return 0;

        // 构建SQL语句，使用占位符 ? 来代表每个ID
        String deleteSQL = ("DELETE FROM "+ tableName +"  WHERE root_url IN $buildInParamList$;")
                .replace("$buildInParamList$", SqlUtils.buildInParamList(rootUrls.size()));

        return runDeleteByStringsSQL(tableName, rootUrls, deleteSQL);
    }

    //基于 msgHash 列表 同时删除多个 行
    public static synchronized int deleteLineByMsgHashList(String tableName, List<String> msgHashList) {
        if (isEmptyObj(msgHashList)) return 0;

        // 构建SQL语句，使用占位符 ? 来代表每个ID
        String deleteSQL = ("DELETE FROM "+ tableName + "  WHERE msg_hash IN $buildInParamList$;")
                .replace("$buildInParamList$", SqlUtils.buildInParamList(msgHashList.size()));

        return runDeleteByStringsSQL(tableName, msgHashList, deleteSQL);
    }

    /**
     * 基于 id 列表 同时删除多个 行
     */
    public static synchronized int deleteLineByIds(String tableName, List<Integer> ids) {
        int totalRowsAffected = 0;

        if (ids.isEmpty()) return totalRowsAffected;

        // 构建SQL语句，使用占位符 ? 来代表每个ID
        String deleteSQL = ("DELETE FROM "+ tableName + " WHERE id IN $buildInParamList$;")
                .replace("$buildInParamList$", SqlUtils.buildInParamList(ids.size()));

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
     * 基于 多个url前缀 列表 删除行
     */
    public static synchronized int deleteLineByUrlLikeRootUrls(String tableName, List<String> rootUrlList) {
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
