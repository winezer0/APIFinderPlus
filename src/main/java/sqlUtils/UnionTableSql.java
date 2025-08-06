package sqlUtils;

import database.AnalyseHostResultTable;
import database.DBService;
import database.PathTreeTable;
import model.FindPathModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class UnionTableSql {
    //联合 获取一条需要更新的Path数据
    public static synchronized List<FindPathModel> fetchHostTableNeedUpdatePathDataList(int limit){
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

}
