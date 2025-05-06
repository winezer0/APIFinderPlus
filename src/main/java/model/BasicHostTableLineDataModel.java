package model;


public class BasicHostTableLineDataModel {
    private Integer id;
    private String rootUrl;
    private String host;

    private Integer findInfoNum;
    private Boolean hasImportant;

    private Integer findUrlNum;
    private Integer findPathNum;
    private Integer findApiNum;

    private Integer pathToUrlNum;
    private Integer unvisitedUrlNum;
    private Integer allUrlNum;
    private Integer basicPathNum;

    private String runStatus;

    // 构造函数
    public BasicHostTableLineDataModel(int id, String rootUrl,
                                       int findInfoNum, boolean hasImportant,
                                       int findUrlNum, int findPathNum, int findApiNum,
                                       int pathToUrlNum, int unvisitedUrlNum,
                                       int allUrlNum, int basicPathNum, String runStatus) {
        this.id = id;
        this.rootUrl = rootUrl;
        this.host = parseDomainFromUrl(rootUrl);
        
        this.findInfoNum = findInfoNum;
        this.hasImportant = hasImportant;


        this.findUrlNum = findUrlNum;
        this.findPathNum = findPathNum;
        this.findApiNum = findApiNum;

        this.pathToUrlNum = pathToUrlNum;
        this.unvisitedUrlNum = unvisitedUrlNum;

        this.allUrlNum = allUrlNum;
        this.basicPathNum = basicPathNum;

        this.runStatus = runStatus;
    }

    private String parseDomainFromUrl(String rootUrl) {
        //从URL中解析出domain
        return new HttpUrlInfo(rootUrl).getRootDomain();
    }


    public Object[] toRowDataArray() {
        return new Object[]{
                this.getId(),
                this.getRootUrl(),
                this.getHost(),
                this.getHasImportant(),
                this.getFindInfoNum(),
                this.getFindUrlNum(),
                this.getFindPathNum(),
                this.getFindApiNum(),
                this.getPathToUrlNum(),
                this.getUnvisitedUrlNum(),
                this.getAllUrlNum(),
                this.getBasicPathNum(),
                this.getRunStatus()
        };
    }

    public Integer getId() {
        return id;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public Integer getFindInfoNum() {
        return findInfoNum;
    }

    public Boolean getHasImportant() {
        return hasImportant;
    }

    public Integer getFindUrlNum() {
        return findUrlNum;
    }

    public Integer getFindPathNum() {
        return findPathNum;
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

    public Integer getBasicPathNum() {
        return basicPathNum;
    }

    public String getRunStatus() {
        return runStatus;
    }

    public Integer getAllUrlNum() {
        return allUrlNum;
    }

    public String getHost() {
        return host;
    }
}
