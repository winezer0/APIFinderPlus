package model;


public class ApiDataModel {
    private int msgId;
    private String msgHash;
    private String reqUrl;
    private String reqMethod;
    private int respStatusCode;
    private String reqSource;
    private int findUrlNum;
    private int findPathNum;
    private int findInfoNum;
    private int findApiNum;
    private int smartApiNum;
    private String runStatus;
    private int basicPathNum;

    // 构造函数
    public ApiDataModel(int msgId, String msgHash, String reqUrl, String reqMethod, int respStatusCode,
                        String reqSource, int findUrlNum, int findPathNum, int findInfoNum,
                        int findApiNum, int smartApiNum, String runStatus, int basicPathNum) {
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
        this.smartApiNum = smartApiNum;
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
                this.getSmartApiNum(),
                this.getRunStatus(),
                this.getBasicPathNum()
        };
    }

    public int getMsgId() {
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

    public int getRespStatusCode() {
        return respStatusCode;
    }

    public String getReqSource() {
        return reqSource;
    }

    public int getFindUrlNum() {
        return findUrlNum;
    }

    public int getFindPathNum() {
        return findPathNum;
    }

    public int getFindInfoNum() {
        return findInfoNum;
    }

    public int getFindApiNum() {
        return findApiNum;
    }

    public int getSmartApiNum() {
        return smartApiNum;
    }

    public String getRunStatus() {
        return runStatus;
    }

    public int getBasicPathNum() {
        return basicPathNum;
    }
}
