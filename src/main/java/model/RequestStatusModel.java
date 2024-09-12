package model;

public class RequestStatusModel {
    private Integer id;
    private String reqUrl;
    private String reqMethod;
    private Integer respStatusCode;
    private Integer respLength;

    // 有参构造函数
    public RequestStatusModel(Integer id, String reqUrl, String reqMethod, Integer respStatusCode, Integer respLength) {
        this.id = id;
        this.reqUrl = reqUrl;
        this.reqMethod = reqMethod;
        this.respStatusCode = respStatusCode;
        this.respLength = respLength;
    }

    public Integer getId() {
        return id;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getReqMethod() {
        return reqMethod;
    }

    public Integer getRespStatusCode() {
        return respStatusCode;
    }

    public Integer getRespLength() {
        return respLength;
    }
}