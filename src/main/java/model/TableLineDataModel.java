package model;


public class TableLineDataModel {
    private Integer msgId;
    private String msgHash;
    private String reqUrl;
    private String reqMethod;
    private Integer respStatusCode;
    private String reqSource;
    private Integer findUrlNum;
    private Integer findPathNum;
    private Integer findInfoNum;
    private Integer findApiNum;
    private Integer pathToUrlNum;
    private Integer unvisitedUrlNum;
    private String runStatus;
    private Integer basicPathNum;

    // 构造函数
    public TableLineDataModel(int msgId, String msgHash, String reqUrl, String reqMethod, int respStatusCode,
                              String reqSource, int findUrlNum, int findPathNum, int findInfoNum,
                              int findApiNum, int pathToUrlNum, int unvisitedUrlNum, String runStatus, int basicPathNum) {
        this.msgId = msgId;
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.reqMethod = reqMethod;
        this.respStatusCode = respStatusCode;
        this.reqSource = reqSource;
        this.findUrlNum = findUrlNum;
        this.findPathNum = findPathNum;
        this.findInfoNum = findInfoNum;
        this.findApiNum = findApiNum;
        this.pathToUrlNum = pathToUrlNum;
        this.unvisitedUrlNum = unvisitedUrlNum;
        this.runStatus = runStatus;
        this.basicPathNum = basicPathNum;
    }

    public Object[] toRowDataArray() {
        return new Object[]{
                this.getMsgId(),
                this.getMsgHash(),
                this.getReqUrl(),
                this.getReqMethod(),
                this.getRespStatusCode(),
                this.getReqSource(),
                this.getFindUrlNum(),
                this.getFindPathNum(),
                this.getFindInfoNum(),
                this.getFindApiNum(),
                this.getPathToUrlNum(),
                this.getUnvisitedUrlNum(),
                this.getRunStatus(),
                this.getBasicPathNum()
        };
    }

    public Integer getMsgId() {
        return msgId;
    }

    public String getMsgHash() {
        return msgHash;
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

    public String getReqSource() {
        return reqSource;
    }

    public Integer getFindUrlNum() {
        return findUrlNum;
    }

    public Integer getFindPathNum() {
        return findPathNum;
    }

    public Integer getFindInfoNum() {
        return findInfoNum;
    }

    public Integer getFindApiNum() {
        return findApiNum;
    }

    public Integer getPathToUrlNum() {
        return pathToUrlNum;
    }

    public Integer getUnvisitedUrlNum() {
        return unvisitedUrlNum;
    }

    public String getRunStatus() {
        return runStatus;
    }

    public Integer getBasicPathNum() {
        return basicPathNum;
    }

}
