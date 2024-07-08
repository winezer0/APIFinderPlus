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
    public static synchronized FindPathModel fetchOneNeedUpdatedSmartApiData(){
        FindPathModel pathData = null;

        // 首先选取一条记录的ID
        String selectSQL = ("SELECT A.id, A.req_url,A.req_host_port, A.find_path " +
                "From table1 A LEFT JOIN table2 B ON A.req_host_port = B.req_host_port " +
                "WHERE A.run_status = 'ANALYSE_ING' AND B.basic_path_num > A.basic_path_num Limit 1;")
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("table1", InfoAnalyseTable.tableName)
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


    //联合 获取一条需要更新的Path数据
    public static synchronized ArrayList<TableLineDataModel> fetchAllReqDataLeftJoinAnalyseInfo(){
        ArrayList<TableLineDataModel> apiDataModels = new ArrayList<>();
        // 获取当前所有记录的数据
        String selectSQL = ("SELECT A.msg_id,A.msg_hash,A.req_url,A.req_method,A.resp_status_code,A.req_source,B.find_url_num," +
                "B.find_path_num,B.find_info_num,B.find_api_num,B.smart_api_num,B.unvisited_url_num,B.run_status,B.basic_path_num " +
                "from table1 A LEFT JOIN table2 B ON A.msg_hash = B.msg_hash order by A.msg_id;")
                .replace("ANALYSE_ING", Constants.ANALYSE_ING)
                .replace("table1", ReqDataTable.tableName)
                .replace("table2", InfoAnalyseTable.tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    TableLineDataModel apiDataModel = new TableLineDataModel(
                            rs.getInt("msg_id"),
                            rs.getString("msg_hash"),
                            rs.getString("req_url"),
                            rs.getString("req_method"),
                            rs.getInt("resp_status_code"),
                            rs.getString("req_source"),
                            rs.getInt("find_url_num"),
                            rs.getInt("find_path_num"),
                            rs.getInt("find_info_num"),
                            rs.getInt("find_api_num"),
                            rs.getInt("smart_api_num"),
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
}
