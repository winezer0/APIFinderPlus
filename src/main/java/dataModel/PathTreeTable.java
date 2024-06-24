package dataModel;

import com.alibaba.fastjson2.JSONObject;

import java.sql.*;

import static model.PathTreeInfo.deepMerge;
import static utils.BurpPrintUtils.*;

public class PathTreeTable {
    //数据表名称
    static String tableName = "PATH_TREE";

    //创建 基于 record_urls 生成的每个域名的 路径结构 树
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + " req_host_port TEXT NOT NULL,\n"    //请求域名:端口
            + " path_tree TEXT NOT NULL,\n"   //根树的序列化Json数据
            + " path_num INTEGER NOT NULL DEFAULT 0\n"  //基于多少个路径计算出来的根树,最好使用根树的稳定 hash
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdatePathTree(JSONObject treeObj) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String reqHost = (String) treeObj.get(Constants.REQ_HOST_PORT);
        Integer pathNum = (Integer) treeObj.get(Constants.PATH_NUM);
        JSONObject pathTree = (JSONObject) treeObj.get(Constants.PATH_TREE);

        //查询
        String checkSql = "SELECT * FROM tableName WHERE req_host_port = ?"
                .replace("tableName", tableName);

        //插入
        String insertSql = "INSERT INTO tableName (req_host_port, path_tree, path_num) VALUES (?, ?, ?)"
                .replace("tableName", tableName);

        //更新
        String updateSQL = "UPDATE tableName SET path_tree = ?, path_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            checkStmt.setString(1, reqHost);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                //记录存在,需要更新
                int selectedId = rs.getInt("id");
                String oldPathTree = rs.getString("path_tree");
                int oldPathNum = rs.getInt("path_num");

                //合并新旧Json树
                JSONObject newTree = pathTree;
                if (oldPathTree != null && oldPathTree != ""){
                    JSONObject oldTree = JSONObject.parse(oldPathTree);
                    newTree = deepMerge(oldTree, pathTree);
                }

                //合并新旧path num
                int newPathNum = pathNum;
                if (newPathNum > 0)
                    newPathNum = oldPathNum + pathNum;

                //更新索引对应的数据
                try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                    updateStatement.setString(1, newTree.toJSONString());
                    updateStatement.setInt(2, newPathNum);
                    updateStatement.setInt(3, selectedId);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        generatedId = selectedId;
                    }
                }
            } else {
                // 记录不存在，插入新记录
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, reqHost);
                    insertStmt.setString(2, pathTree.toJSONString());
                    insertStmt.setInt(3, pathNum);
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

}
