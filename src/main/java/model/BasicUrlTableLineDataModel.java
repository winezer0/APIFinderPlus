package model;


public class BasicUrlTableLineDataModel {
    private Integer id;
    private String msgHash;
    private String reqUrl;
    private String reqMethod;
    private Integer respStatusCode;
    private String reqSource;
    private Integer findUrlNum;
    private Integer findPathNum;
    private Integer findInfoNum;
    private Integer findApiNum;
    private String runStatus;
    private Integer basicPathNum;
    private Integer respLength;
    private Boolean hasImportant;
    // 构造函数
    public BasicUrlTableLineDataModel(int id, String msgHash, String reqUrl, String reqMethod, int respStatusCode,
                                      String reqSource, int findUrlNum, int findPathNum, int findInfoNum,
                                      boolean hasImportant, int findApiNum, String runStatus, int basicPathNum, int respLength) {
        this.id = id;
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.reqMethod = reqMethod;
        this.respStatusCode = respStatusCode;
        this.reqSource = reqSource;
        this.findUrlNum = findUrlNum;
        this.findPathNum = findPathNum;
        this.findInfoNum = findInfoNum;
        this.findApiNum = findApiNum;
        this.runStatus = runStatus;
        this.basicPathNum = basicPathNum;
        this.respLength = respLength;
        this.hasImportant = hasImportant;
    }

    public Object[] toRowDataArray() {
        return new Object[]{
                this.getId(),
                this.getReqSource(),
                this.getMsgHash(),
                this.getReqUrl(),
                this.getReqMethod(),
                this.getRespStatusCode(),
                this.getRespLength(),
                this.getHasImportant(),
                this.getFindInfoNum(),
                this.getFindUrlNum(),
                this.getFindPathNum(),
                this.getFindApiNum(),
                this.getBasicPathNum(),
                this.getRunStatus()
        };
    }

    public Integer getId() {
        return id;
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

    public String getRunStatus() {
        return runStatus;
    }

    public Integer getBasicPathNum() {
        return basicPathNum;
    }

    public Integer getRespLength() {
        return respLength;
    }

    public Boolean getHasImportant() {
        return hasImportant;
    }


}
