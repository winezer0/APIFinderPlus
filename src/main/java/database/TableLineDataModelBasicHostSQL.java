package database;

import model.BasicHostTableLineDataModel;
import model.BasicHostTableTabDataModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;

import static utils.BurpPrintUtils.LOG_ERROR;
import static utils.BurpPrintUtils.stderr_println;

/**
 * 存储基于主机相关的SQL查询函数
 */
public class TableLineDataModelBasicHostSQL {


    private static String genHostTableSqlByWhereCondition(String WhereCondition){
        String selectSQL = ("SELECT id,root_url,find_info_num,has_important,find_url_num,find_path_num,find_api_num,path_to_url_num,unvisited_url_num,basic_path_num,run_status FROM $tableName$;")
                .replace("$tableName$", AnalyseHostResultTable.tableName);
        if (WhereCondition == null) WhereCondition= "";
        return selectSQL.replace("$WHERE$", WhereCondition);
    }

    //联合 获取所有行数据
    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataBySQl(String selectSQL){
        ArrayList<BasicHostTableLineDataModel> apiDataModels = new ArrayList<>();

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    BasicHostTableLineDataModel apiDataModel = new BasicHostTableLineDataModel(
                            rs.getInt("id"),
                            rs.getString("root_url"),
                            rs.getInt("find_info_num"),
                            rs.getBoolean("has_important"),
                            rs.getInt("find_url_num"),
                            rs.getInt("find_path_num"),
                            rs.getInt("find_api_num"),
                            rs.getInt("path_to_url_num"),
                            rs.getInt("unvisited_url_num"),
                            rs.getInt("basic_path_num"),
                            rs.getString("run_status")
                    );
                    apiDataModels.add(apiDataModel);
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Fetch All ReqData Left Join InfoAnalyse On SQL: %s", e.getMessage()));
        }
        return apiDataModels;
    }

    // 获取当前所有记录
    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataAll() {
        String selectSQL = genHostTableSqlByWhereCondition(null);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }

    //获取有效数据的行
    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataHasData() {
        // 获取当前所有记录的数据
        String WhereCondition = "Where find_url_num>0 or find_path_num>0 or find_info_num>0";
        String selectSQL = genHostTableSqlByWhereCondition(WhereCondition);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }

    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataHasInfo() {
        // 获取当前所有记录的数据
        String WhereCondition = "where find_info_num>0";
        String selectSQL = genHostTableSqlByWhereCondition(WhereCondition);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }

    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataHasUnVisitedUrls() {
        // 获取当前所有记录的数据
        String WhereCondition = "where unvisited_url_num>0";
        String selectSQL = genHostTableSqlByWhereCondition(WhereCondition);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }

    public static synchronized ArrayList<BasicHostTableLineDataModel> fetchHostTableLineDataIsNull() {
        // 获取当前所有记录的数据
        String WhereCondition = "where (find_url_num is null and find_path_num is null and find_info_num is null) or (find_url_num <1  and find_path_num <1 and find_info_num <1) ";
        String selectSQL = genHostTableSqlByWhereCondition(WhereCondition);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }
}
