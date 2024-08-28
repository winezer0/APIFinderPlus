package database;

import model.FindPathModel;
import model.TableLineDataModelBasicUrl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class UnionTableSql {
    //联合 获取一条需要更新的Path数据
    public static synchronized List<FindPathModel> fetchNeedUpdatePathDataList(int limit){
        List<FindPathModel> findPathModels = new ArrayList<>();

        // 首先选取一条记录的ID 状态是已经分析完毕,并且 当前 PathTree 的 基本路径数量 大于 生成分析数据时的 基本路径数量
        String selectSQL = ("SELECT A.id, A.root_url, A.find_path " +
                "From $tableName1$ A LEFT JOIN $tableName2$ B ON A.root_url = B.root_url " +
                "WHERE B.basic_path_num > A.basic_path_num Limit ?;")
                .replace("$tableName1$", AnalyseHostResultTable.tableName)
                .replace("$tableName2$", PathTreeTable.tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setInt(1, limit);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    FindPathModel  findPathModel = new FindPathModel(
                            rs.getInt("id"),
                            rs.getString("root_url"),
                            rs.getString("find_path")
                    );
                    findPathModels.add(findPathModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-]  Error fetch Need Update Path Data List: %s", e.getMessage()));
        }
        return findPathModels;
    }

    //联合 获取所有行数据
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchUrlTableLineDataBySQl(String selectSQL){
        ArrayList<TableLineDataModelBasicUrl> apiDataModels = new ArrayList<>();

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    TableLineDataModelBasicUrl apiDataModel = new TableLineDataModelBasicUrl(
                            rs.getInt("id"),
                            rs.getString("msg_hash"),
                            rs.getString("req_url"),
                            rs.getString("req_method"),
                            rs.getInt("resp_status_code"),
                            rs.getString("req_source"),
                            rs.getInt("find_url_num"),
                            rs.getInt("find_path_num"),
                            rs.getInt("find_info_num"),
                            rs.getBoolean("has_important"),
                            rs.getInt("find_api_num"),
                            rs.getInt("path_to_url_num"),
                            rs.getInt("unvisited_url_num"),
                            rs.getString("run_status"),
                            rs.getInt("basic_path_num"),
                            rs.getInt("resp_length")
                    );
                    apiDataModels.add(apiDataModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Fetch All ReqData Left Join InfoAnalyse On MsgHash: %s", e.getMessage()));
        }
        return apiDataModels;
    }

    private static String genSqlByWhereCondition(String WhereCondition){
        String selectSQL = ("SELECT A.id,A.msg_hash,A.req_url,A.req_method,A.resp_status_code,A.req_source,A.run_status,A.resp_length," +
                "B.find_url_num,B.find_path_num,B.find_info_num,B.has_important,B.find_api_num,B.path_to_url_num,B.unvisited_url_num,B.basic_path_num " +
                "from $tableName1$ A LEFT JOIN $tableName2$ B ON A.msg_hash = B.msg_hash $WHERE$ order by A.id;")
                .replace("$tableName1$", ReqDataTable.tableName)
                .replace("$tableName2$", AnalyseUrlResultTable.tableName);

        if (WhereCondition == null) WhereCondition="";

        return selectSQL.replace("$WHERE$", WhereCondition);
    }

    // 获取当前所有记录
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchUrlTableLineDataAll() {
        String selectSQL = genSqlByWhereCondition(null);
        return  fetchUrlTableLineDataBySQl(selectSQL);
    }

    //获取有效数据的行
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchUrlTableLineDataHasData() {
        // 获取当前所有记录的数据
        String WhereCondition = "Where find_url_num>0 or find_path_num>0 or find_info_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchUrlTableLineDataBySQl(selectSQL);
    }

    //获取还有未访问完毕的URL的行
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchTableLineDataHasUnVisitedUrls() {
        // 获取当前所有记录的数据
        String WhereCondition = "where unvisited_url_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchUrlTableLineDataBySQl(selectSQL);
    }

    //获取存在敏感信息的行
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchTableLineDataHasInfo() {
        // 获取当前所有记录的数据
        String WhereCondition = "where find_info_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchUrlTableLineDataBySQl(selectSQL);
    }

    //获取没有数据的行,备用,用于后续删除数据
    public static synchronized ArrayList<TableLineDataModelBasicUrl> fetchTableLineDataIsNull() {
        // 获取当前所有记录的数据
        String WhereCondition = "where (find_url_num is null and find_path_num is null and find_info_num is null) or (find_url_num <1  and find_path_num <1 and find_info_num <1) ";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchUrlTableLineDataBySQl(selectSQL);
    }

    //获取没有数据的行,备用,用于后续删除数据
    public static synchronized int clearUselessData() {
        int rowsAffected = -1;

        // 获取当前所有记录的数据
        String deleteSQL = ("DELETE FROM $tableName1$ WHERE id IN (" +
                "SELECT A.id FROM $tableName1$ A LEFT JOIN $tableName2$ B ON A.msg_hash=B.msg_hash " +
                "WHERE (find_url_num IS NULL AND find_path_num IS NULL AND find_info_num IS NULL) " +
                "OR (find_url_num < 1 AND find_path_num < 1 AND find_info_num < 1));")
                .replace("$tableName1$", ReqDataTable.tableName)
                .replace("$tableName2$", AnalyseUrlResultTable.tableName);

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(deleteSQL)) {
            rowsAffected = stmt.executeUpdate();
            stdout_println(LOG_DEBUG, String.format(String.format("[-] table [%s] cleared Useless Data [%s] line.", ReqDataTable.tableName, rowsAffected)));
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error clear Useless Data On Table [%s] -> Error:[%s]", ReqDataTable.tableName, e.getMessage()));
            e.printStackTrace();
        }

        return rowsAffected;
    }

}
