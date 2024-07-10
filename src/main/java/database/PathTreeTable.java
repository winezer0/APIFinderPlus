package database;

import com.alibaba.fastjson2.JSONObject;

import java.sql.*;

import static utils.PathTreeUtils.deepMergeJsonTree;
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
            + " basic_path_num INTEGER NOT NULL DEFAULT 0\n"  //基于多少个路径计算出来的根树,最好使用根树的稳定 hash
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdatePathTree(JSONObject treeObj) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String reqHost = (String) treeObj.get(Constants.REQ_HOST_PORT);
        Integer basicPathNum = (Integer) treeObj.get(Constants.BASIC_PATH_NUM);
        JSONObject pathTree = (JSONObject) treeObj.get(Constants.PATH_TREE);

        //查询
        String checkSql = "SELECT * FROM tableName WHERE req_host_port = ?;"
                .replace("tableName", tableName);

        //插入
        String insertSql = "INSERT INTO tableName (req_host_port, path_tree, basic_path_num) VALUES (?, ?, ?);"
                .replace("tableName", tableName);

        //更新
        String updateSQL = "UPDATE tableName SET path_tree = ?, basic_path_num = ? WHERE id = ?;"
                .replace("tableName", tableName);

        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            checkStmt.setString(1, reqHost);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                //记录存在,需要更新
                int selectedId = rs.getInt("id");
                String oldPathTree = rs.getString("path_tree");
                int oldBasicPathNum = rs.getInt("basic_path_num");

                //合并新旧Json树
                JSONObject newTree = pathTree;
                if (oldPathTree != null && oldPathTree != ""){
                    JSONObject oldTree = JSONObject.parse(oldPathTree);
                    newTree = deepMergeJsonTree(oldTree, pathTree);
                }

                //合并新旧path num
                int newBasicPathNum = basicPathNum;
                if (newBasicPathNum > 0)
                    newBasicPathNum = oldBasicPathNum + basicPathNum;

                //更新索引对应的数据
                try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                    updateStatement.setString(1, newTree.toJSONString());
                    updateStatement.setInt(2, newBasicPathNum);
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
                    insertStmt.setInt(3, basicPathNum);
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


    //根据域名查询对应的Host
    public static synchronized JSONObject fetchOnePathTreeData(String reqHost) {
        //查询
        String checkSql = "SELECT * FROM tableName WHERE req_host_port = ? LIMIT 1;"
                .replace("tableName", tableName);

        JSONObject pathTreeData = new JSONObject();
        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            checkStmt.setString(1, reqHost);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                pathTreeData.put(Constants.PATH_TREE, rs.getString("path_tree"));
                pathTreeData.put(Constants.BASIC_PATH_NUM, rs.getInt("basic_path_num"));
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error Fetch One table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return pathTreeData;
    }

}
