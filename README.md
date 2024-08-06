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


### TODO

```
暂未实现自动化的 webpack 封装JS内容分析
```

