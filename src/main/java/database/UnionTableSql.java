package database;

import model.FindPathModel;
import model.TableLineDataModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;

import static utils.BurpPrintUtils.LOG_ERROR;
import static utils.BurpPrintUtils.stderr_println;

public class UnionTableSql {
    //联合 获取一条需要更新的Path数据
    public static synchronized FindPathModel fetchOneNeedUpdatedPathToUrlData(){
        FindPathModel pathData = null;

        // 首先选取一条记录的ID 状态是已经分析完毕,并且 当前 PathTree 的 基本路径数量 大于 生成分析数据时的 基本路径数量
        String selectSQL = ("SELECT A.id, A.req_url,A.req_host_port, A.find_path " +
                "From table1 A LEFT JOIN table2 B ON A.req_host_port = B.req_host_port " +
                "WHERE A.run_status = 'ANALYSE_ING' AND B.basic_path_num > A.basic_path_num Limit 1;")
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("table1", AnalyseResultTable.tableName)
                .replace("table2", PathTreeTable.tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    pathData = new FindPathModel(
                            rs.getInt("id"),
                            rs.getString("req_url"),
                            rs.getString("req_host_port"),
                            rs.getString("find_path")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Path Data: %s", e.getMessage()));
        }
        return pathData;
    }


    //联合 获取所有行数据
    public static synchronized ArrayList<TableLineDataModel> fetchTableLineDataBySQl(String selectSQL){
        ArrayList<TableLineDataModel> apiDataModels = new ArrayList<>();

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    TableLineDataModel apiDataModel = new TableLineDataModel(
                            rs.getInt("id"),
                            rs.getString("msg_hash"),
                            rs.getString("req_url"),
                            rs.getString("req_method"),
                            rs.getInt("resp_status_code"),
                            rs.getString("req_source"),
                            rs.getInt("find_url_num"),
                            rs.getInt("find_path_num"),
                            rs.getInt("find_info_num"),
                            rs.getInt("find_api_num"),
                            rs.getInt("path_to_url_num"),
                            rs.getInt("unvisited_url_num"),
                            rs.getString("run_status"),
                            rs.getInt("basic_path_num")
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
        String selectSQL = ("SELECT A.id,A.msg_hash,A.req_url,A.req_method,A.resp_status_code,A.req_source,A.run_status," +
                "B.find_url_num,B.find_path_num,B.find_info_num,B.find_api_num,B.path_to_url_num,B.unvisited_url_num,B.basic_path_num " +
                "from table1 A LEFT JOIN table2 B ON A.msg_hash = B.msg_hash $WHERE$ order by A.id;")
                .replace("table1", ReqDataTable.tableName)
                .replace("table2", AnalyseResultTable.tableName);

        if (WhereCondition == null) WhereCondition="";

        return selectSQL.replace("$WHERE$", WhereCondition);
    }

    // 获取当前所有记录
    public static ArrayList<TableLineDataModel> fetchTableLineDataAll() {
        String selectSQL = genSqlByWhereCondition(null);
        return  fetchTableLineDataBySQl(selectSQL);
    }

    //获取有效数据的行
    public static ArrayList<TableLineDataModel> fetchTableLineDataHasData() {
        // 获取当前所有记录的数据
        String WhereCondition = "Where find_url_num>0 or find_path_num>0 or find_info_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchTableLineDataBySQl(selectSQL);
    }

    //获取还有未访问完毕的URL的行
    public static ArrayList<TableLineDataModel> fetchTableLineDataHasUnVisitedUrls() {
        // 获取当前所有记录的数据
        String WhereCondition = "where unvisited_url_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchTableLineDataBySQl(selectSQL);
    }

    //获取存在敏感信息的行
    public static ArrayList<TableLineDataModel> fetchTableLineDataHasInfo() {
        // 获取当前所有记录的数据
        String WhereCondition = "where find_info_num>0";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchTableLineDataBySQl(selectSQL);
    }

    //获取没有数据的行,备用,用于后续删除数据
    public static ArrayList<TableLineDataModel> fetchTableLineDataIsNull() {
        // 获取当前所有记录的数据
        String WhereCondition = "where (find_url_num is null and find_path_num is null and find_info_num is null) or (find_url_num <1  and find_path_num <1 and find_info_num <1) ";
        String selectSQL = genSqlByWhereCondition(WhereCondition);
        return  fetchTableLineDataBySQl(selectSQL);
    }
}
