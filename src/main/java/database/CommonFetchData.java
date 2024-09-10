package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class CommonFetchData {
    /**
     * 统计数据表行数大小
     */
    public static synchronized int fetchTableCounts(String tableName) {
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
     * 统计所有已经识别完成的URL的数量
     * @return
     */
    public static synchronized int fetchTableCountsByStatus(String analyseStatus) {
        int count = 0;

        String selectSQL = "SELECT COUNT(*) FROM "+ ReqDataTable.tableName + " WHERE run_status = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)){
            stmt.setString(1, analyseStatus);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                count = rs.getInt(1); // 获取第一列的值，即 COUNT(*) 的结果
            }
        } catch (Exception e) {
            stderr_println(String.format("Counts Table [%s] Error: %s", ReqDataTable.tableName, e.getMessage() ));
        }
        return count;
    }

    /**
     * 根据运行状态取获取对应 ID list
     */
    public static synchronized List<Integer> fetchIdsByRunStatus(String tableName, String analyseStatus, int limit) {
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
     * 根据运行状态取获取对应请求 msghash list
     * @return
     */
    public static synchronized List<String> fetchMsgHashByRunStatus(String tableName, String analyseStatus, int limit) {
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

    /////////////////////////////
    /**
     * 获取任意表的任意列的字符串列表 【基于msgHashList】
     */
    public static synchronized List<String> fetchColumnStrListByMsgHashList(String tableName, String columnName, List<String> msgHashList) {
        List<String> stringList = new ArrayList<>();

        if (msgHashList.isEmpty())
            return stringList;

        String selectSQL = "SELECT " + columnName + " FROM "+ tableName +" WHERE msg_hash IN $buildInParameterList$;"
                .replace("$buildInParameterList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    stringList.add(rs.getString(columnName));
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] fetchColumnStrListByMsgHashList: [%s] [%s] -> Error: %s",tableName, columnName, e.getMessage()));
        }
        return stringList;
    }
    /////////////////////////////
    /**
     * 获取任意表的任意列的字符串拼接 【获取所有行】
     */
    public static synchronized String fetchColumnGroupConcatString(String tableName, String columnName) {
        String concatenatedURLs = null;

        String concatSQL = ("SELECT GROUP_CONCAT($columnName$,',') AS concatenated_urls FROM "+ tableName +";")
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

    /**
     * 获取任意表的任意列的字符串拼接 InRootUrls
     */
    public static synchronized String fetchColumnGroupConcatStringInRootUrls(String tableName, String columnName, List<String> rootUrls) {
        String concatenatedURLs = null;

        String concatSQL = ("SELECT GROUP_CONCAT($columnName$,',') AS concatenated_urls FROM "+ tableName +
                " WHERE root_url IN $buildInParameterList$;")
                        .replace("$columnName$",columnName)
                        .replace("$buildInParameterList$", DBService.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(concatSQL)) {
            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 1, rootUrls.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                concatenatedURLs = rs.getString("concatenated_urls");
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] [%s] Column Group Concat String In RootUrls concatenating: %s",tableName, columnName, e.getMessage()));
            e.printStackTrace();
        }
        return concatenatedURLs;
    }

    /**
     * 获取任意表的任意列的字符串拼接 NotInRootUrls
     */
    public static synchronized String fetchColumnGroupConcatStringNotInRootUrls(String tableName, String columnName, List<String> rootUrls) {
        String concatenatedURLs = null;

        String concatSQL = ("SELECT GROUP_CONCAT($columnName$,',') AS concatenated_urls FROM "+ tableName +
                " WHERE root_url NOT IN $buildInParameterList$;")
                .replace("$columnName$",columnName)
                .replace("$buildInParameterList$", DBService.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(concatSQL)) {
            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 1, rootUrls.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                concatenatedURLs = rs.getString("concatenated_urls");
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] [%s] Column Group Concat String Not In RootUrls concatenating: %s",tableName, columnName, e.getMessage()));
            e.printStackTrace();
        }
        return concatenatedURLs;
    }
}
