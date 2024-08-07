# BurpAPIFinder-Refactor

本插件参考 APIFinder [https://github.com/shuanx/BurpAPIFinder] 进行深度重构开发


### 插件目标

```
做最全面的API挖掘工具、减少手动拼接path的提取测试.

1、支持 响应 信息中的敏感信息、URL、URI信息提取.
2、支持 自动基于 已知路径信息 计算PATH 对应的实际URL.
3、支持 自动访问 挖掘出来的URL信息 进行递归式的信息提取.
```
### 注意事项

```
做最全面的API挖掘工具、减少手动拼接path的提取测试.

1、所有数据都是存储sqlite进行读写、比内存操作慢一些.
2、执行刷新 未访问URL、自动递归扫描 任务时，占用的内存应该是较大的。
3、因为功能过多，使用请将鼠标悬浮到文本或按钮上，查看操作描述
```

### 运行流程

![APIFinder运行流程](./doc/APIFinder运行流程.png)



### 主要任务

```
定时任务线程：
- 查询数据库 ReqDataTable 表
  - 是否存在未分析的 消息
    - 根据规则配置 匹配 提取 请求|响应中的敏感信息和URL、PATH
      - 分析结果存入数据库 AnalyseResultTable 表
- autoPathsToUrlsIsOpen 开启自动基于路径计算URL功能 (默认关闭、支持手动)
  - 查询数据库  RecordPathTable
    - 检查是否存在没有加入到 网站路径树 的有效请求PATH
      - 根据已记录的URL路径计算/更新Pathree
        - 分析结果存入 PathTree 表
  - 查询数据库 AnalyseResultTable
    - 检查是否存在没有根据PathTree计算PATH实际URL的数据
      - 根据已记录的Pathree计算PATH可能的前缀
        - 分析结果存入  AnalyseResultTable 的 PATH计算URL
  - 查询数据库 联合分析 PathTreeTable 和 AnalyseResultTable 表
    - 检查是否存在已经更新的PathTree 但是还没有重新计算过PATH URL的数据
      - 根据已更新的Pathree计算新的PATH可能的前缀
- autoRecursiveIsOpen 开启自动访问未访问的URL
  - 查询数据库 AnalyseResultTable 表
    - 判断是否URL是否都已经被访问
      - 对未访问URL构造HTTP请求
```
### 内部规则说明
```
    注意：对于CONF_开头和location为config的规则，属于内部规则，不用于信息匹配。

    CONF_WHITE_URL_ROOT: 允许扫描的目标RootUrl关键字
    CONF_BLACK_URL_ROOT: 禁止扫描的目标RootUrl关键字
    CONF_BLACK_URL_PATH: 禁止进行扫描的目标URL路径关键字
    CONF_BLACK_URL_EXT: 禁止进行扫描的目标URL文件扩展名
    CONF_BLACK_AUTO_RECORD_PATH: 禁止自动进行有效PATH记录的目标RootUrl关键字
    CONF_BLACK_AUTO_RECURSE_SCAN: 禁止自动进行未访问URL扫描的目标RootUrl关键字
    CONF_WHITE_RECORD_PATH_STATUS: 允许自动进行有效PATH记录的响应状态码
    CONF_BLACK_RECORD_PATH_TITLE: 禁止自动进行有效PATH记录的响应标题
    CONF_BLACK_EXTRACT_PATH_KEYS: 禁止提取的URI路径[包含]此项任一元素
    CONF_BLACK_EXTRACT_PATH_EQUAL: 禁止提取的URI路径[等于]此项任一元素
    CONF_BLACK_EXTRACT_INFO_KEYS: 禁止提取的敏感信息[包含]此项任一元素
    CONF_REGULAR_EXTRACT_URIS: 提取响应URI|URL的正则表达式
```

### 匹配规则说明

```
匹配方法("match"字段)： 
    1、关键字匹配 （"match": "keyword"）
    2、正则匹配 （"match": "regular",）

实际匹配规则（"keyword" : [] 列表）：
     1、关键字匹配规则编写
        每行是一个关键字提取匹配规则、
        每行的内容由多个关键字拼接组成，拼接符号是 【|】 
		举例：
		    "keyword": ["fzhm|total|rows" ],
			 表示要求 同时含有 fzhm、total、rows 关键字
        注意：
            1、本规则和原版的有差异，
            2、由于使用了拼接符号 【|】 ，因此不能让匹配关键字中包含【|】
     2、正则匹配规则编写 
        每行是一个正则提取匹配规则

匹配位置("location" 字段)：
    locations = {"path", "body", "header", "response", "config"};
    path 请求路径
    body 响应正文
    header 响应头
    response 全部响应内容
    config 配置规则、不参与匹配

其他关键字：
    "accuracy": 规则准确度
    "describe": 规则描述
    "isImportant": 匹配结果是否重要信
    "isOpen": 是否启用规则
    "type": 规则类型
```


### TODO

```
暂未实现自动化的 webpack 封装JS内容分析
```

