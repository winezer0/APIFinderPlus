package model;

import com.alibaba.fastjson2.JSON;
import utils.CastUtils;
import utils.RespHashUtils;

import java.util.*;

/**
 * 用于响应信息对比的数据模型
 */
public class RespFieldsModel {
    private Integer statusCode;          // 响应状态码,需要忽略 200 的情况
    private Integer respLength;          // 响应头中的长度  需要忽略小于0的情况
    private Integer respBodyLength;        // 响应内容大小
    private String respTextTitle;       // 响应文本标题
    private String respHashContent;     // 响应内容HASH
    private String respRedirectUrl;     // 响应重定向URL

    public RespFieldsModel(HttpRespInfo respInfo) {
        this.statusCode = respInfo.getStatusCode();
        this.respLength = respInfo.getRespLength();
        this.respBodyLength = respInfo.getBodyLength();
        this.respTextTitle = respInfo.getRespTitle();
        this.respRedirectUrl = CastUtils.parseRespRedirectUrl(respInfo.getHeaderBytes());
        this.respHashContent = RespHashUtils.calcCRC32(respInfo.getBodyBytes());
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


}
