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
    static String genSqlByWhereCondition(String WhereCondition){
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
        String selectSQL = genSqlByWhereCondition(null);
        return  fetchHostTableLineDataBySQl(selectSQL);
    }

    /**
     * 获取 指定 msgHash 对应的 所有 分析结果 数据, 用于填充 UI 表的下方 tab 数据
     */
    public static synchronized BasicHostTableTabDataModel fetchResultByRootUrl(String rootUrl){
        BasicHostTableTabDataModel tabDataModel = null;
        String selectSQL = "SELECT * FROM " + AnalyseHostResultTable.tableName +" WHERE root_url = ?;";
        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, rootUrl);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    tabDataModel = new BasicHostTableTabDataModel(
                            rs.getString("root_url"),
                            rs.getString("find_info"),
                            rs.getString("find_url"),
                            rs.getString("find_path"),
                            rs.getString("find_api"),
                            rs.getString("path_to_url"),
                            rs.getString("unvisited_url")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Host Analyse Result Data By RootUrl: %s",  e.getMessage()));
        }
        return tabDataModel;
    }
}
