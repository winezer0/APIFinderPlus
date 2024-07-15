package test;

import com.alibaba.fastjson2.JSON;
import model.HttpRespInfo;
import utils.CastUtils;

import java.util.*;

/**
 * 用于响应信息对比的数据模型
 */
public class RespInfoCompareModel {
    private int statusCode = -1;          // 响应状态码,需要忽略 200 的情况
    private int respLength = -1;          // 响应头中的长度  需要忽略小于0的情况
    private int respBodyLength = -1;        // 响应内容大小
    private String respTextTitle;       // 响应文本标题
    private String respHashContent;     // 响应内容HASH
    private String respRedirectUrl;     // 响应重定向URL

    //构造函数
    public RespInfoCompareModel(int statusCode, int respLength, int respBodyLength, String respTextTitle, String respContentHash, String respRedirectUrl) {
        this.statusCode = statusCode;
        this.respLength = respLength;
        this.respBodyLength = respBodyLength;
        this.respTextTitle = respTextTitle;
        this.respHashContent = respContentHash;
        this.respRedirectUrl = respRedirectUrl;
    }

    public RespInfoCompareModel(HttpRespInfo respInfo) {
        this.statusCode = respInfo.getStatusCode();
        this.respLength = respInfo.getRespLength();
        this.respBodyLength = respInfo.getBodyLength();

        this.respTextTitle =CastUtils.parseTextTitle(respInfo.getBodyBytes());
        this.respRedirectUrl = CastUtils.parseRespRedirectUrl(respInfo.getHeaderBytes());
        this.respHashContent = CastUtils.calcCRC32(respInfo.getBodyBytes());
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getRespLength() {
        return respLength;
    }

    public int getRespBodyLength() {
        return respBodyLength;
    }

    public String getRespTextTitle() {
        return respTextTitle;
    }

    public String getRespHashContent() {
        return respHashContent;
    }

    public String getRespRedirectUrl() {
        return respRedirectUrl;
    }

    public String toJSONString(){
        return JSON.toJSONString(getAllFieldsAsMap());
    }

    // 新增方法：获取所有属性的名称和值
    public Map<String, Object> getAllFieldsAsMap() {
        Map<String, Object> fieldMap = new HashMap<>();
        fieldMap.put("StatusCode", statusCode);
        fieldMap.put("RespLength", respLength);
        fieldMap.put("BodyLength", respBodyLength);
        fieldMap.put("RespTitle", respTextTitle);
        fieldMap.put("RespHash", respHashContent);
        fieldMap.put("RedirectUrl", respRedirectUrl);
        return fieldMap;
    }

    /**
     * 实际用来对比的模型数据
     * @param responses
     * @return
     */
    public static Map<String, Object> findCommonFieldValues(List<RespInfoCompareModel> responses) {
        if (responses == null || responses.size() <= 1) {
            return Collections.emptyMap();
        }

        // 获取第一个对象的字段映射，用于参考
        Map<String, Object> referenceFields = responses.get(0).getAllFieldsAsMap();
        Map<String, Object> commonFields = new HashMap<>();

        // 遍历所有字段
        for (Map.Entry<String, Object> entry : referenceFields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();

            // 检查所有对象的该字段是否具有相同的值
            boolean allMatch = responses.stream()
                    .allMatch(response -> fieldValue.equals(response.getAllFieldsAsMap().get(fieldName)));

            if (allMatch) {
                commonFields.put(fieldName, fieldValue);
            }
        }

        return commonFields;
    }

}
