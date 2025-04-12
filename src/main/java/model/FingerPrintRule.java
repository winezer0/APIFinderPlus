package model;

import utils.CastUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class FingerPrintRule {
    private String matchType;
    private String location;
    private String describe;
    private List<String> matchKeys;
    private boolean isImportant;
    private String type;
    private boolean isOpen;
    private String accuracy;
    
    // 新添加的构造函数
    public FingerPrintRule(String type, String describe, boolean isImportant, String matchType, String location, List<String> matchKeys, boolean isOpen, String accuracy) {
        this.matchType = matchType;
        this.describe = describe;
        this.location = location;
        this.matchKeys = matchKeys;
        this.type = type;
        this.isImportant = isImportant;
        this.isOpen = isOpen;
        this.accuracy = accuracy;
    }

    public boolean getIsOpen(){
        return isOpen;
    }

    public void setOpen(boolean isOpen){
        this.isOpen = isOpen;
    }

    public String getAccuracy(){
        return accuracy;
    }

    public void setAccuracy(String accuracy){
        this.accuracy = accuracy;
    }

    public String getDescribe(){return describe;}

    public void setDescribe(String describe){
        this.describe = describe;
    }

    public String getType(){return type;}

    public void setType(String type){this.type = type;}

    public boolean getIsImportant(){return isImportant;}

    public void setIsImportant(boolean isImportant){this.isImportant = isImportant;}

    public String getMatchType() {
        return matchType;
    }

    public void setMatchType(String matchType) {
        this.matchType = matchType;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public List<String> getMatchKeys() {
        return matchKeys;
    }

    public void setMatchKeys(List<String> matchKeys) {
        this.matchKeys = matchKeys;
    }

    public String getInfo(String color){
        return "Time: " + new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "<br>matchType: " + matchType + "<br>Type: " + type + "<br>accuracy: " + accuracy + "<br>describe: <span style='color: " + color + ";'>" + describe +  "</span><br>location: " + location + "<br>matchKeys: " + CastUtils.listToString(matchKeys) + "<br>";
    }
}
