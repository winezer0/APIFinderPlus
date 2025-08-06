package database;

public class SqlUtils {
    /**
     * 构建一个函数,实现根据参数列表数量自动拼接 IN (?,?,?)语句
     * @param size
     * @return
     */
    public static String buildInParamList(int size) {
        StringBuilder inParameterList = new StringBuilder(" (");
        for (int i = 0; i < size; i++) {
            inParameterList.append("?");
            if (i < size - 1) {
                inParameterList.append(", ");
            }
        }
        inParameterList.append(") ");
        return inParameterList.toString();
    }
}
