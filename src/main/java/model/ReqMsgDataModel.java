package model;

public class ReqMsgDataModel {
    private String msgHash;
    private String reqUrl;
    private byte[] reqBytes;
    private byte[] respBytes;

    public ReqMsgDataModel(String msgHash, String reqUrl, byte[] reqBytes, byte[] respBytes) {
        this.msgHash = msgHash;
        this.reqUrl = reqUrl;
        this.reqBytes = reqBytes;
        this.respBytes = respBytes;
    }

    public String getMsgHash() {
        return msgHash;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public byte[] getReqBytes() {
        return reqBytes;
    }

    public byte[] getRespBytes() {
        return respBytes;
    }
}
