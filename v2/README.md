# GOGO 扫描器

GOGO 是一个高效的网络扫描工具，用于信息收集和安全评估。本文档旨在帮助你理解项目结构和学习如何使用该工具。

## 项目结构

```
gogo/v2/
├── cmd/        - 命令行工具相关代码
├── core/       - 核心功能实现
├── engine/     - 扫描引擎实现
├── pkg/        - 公共包和工具函数
├── templates/  - 模板文件
└── example/    - 示例代码
```

### 核心组件

- **cmd**: 命令行入口和参数解析
- **core**: 核心功能实现，包括Runner、扫描模式等
- **engine**: 扫描引擎，包含各种协议和服务的扫描实现
- **pkg**: 公共包，包含结果处理、配置管理等工具

## 核心功能解析

### 入口函数

```1:30:gogo.go
// 主程序入口函数
func main() {
    // TODO @v2 main函数中的注释代码是性能分析相关功能，后续可以研究
    cmd.Gogo()
}
```

### 命令执行

```1:47:cmd/cmd.go
// Gogo 函数是程序的核心入口点
func Gogo() {
    // 创建Runner对象
    var runner core.Runner
    defer os.Exit(0)
    
    // 解析命令行参数
    parser := flags.NewParser(&runner, flags.Default)
    parser.Usage = core.Usage()
    _, err := parser.Parse()
    if err != nil {
        if err.(*flags.Error).Type != flags.ErrHelp {
            fmt.Println(err.Error())
        }
        return
    }
    
    // 准备运行环境
    if ok := runner.Prepare(); !ok {
        os.Exit(0)
    }
    
    // 显示Banner
    logs.Log.Important(core.Banner())
    
    // 初始化运行环境
    err = runner.Init()
    if err != nil {
        logs.Log.Error(err.Error())
        return
    }
    
    // 执行扫描
    runner.Run()

    // 根据是否为调试模式决定是否删除.sock.lock文件
    if runner.Debug {
        logs.Log.Close(false)
    } else {
        logs.Log.Close(true)
    }
}
```

### Runner结构及核心方法

```37:48:core/runner.go
// Runner 结构是GOGO扫描器的核心，包含所有运行时配置和状态
type Runner struct {
    MiscOption    `group:"Miscellaneous Options"`
    InputOption   `group:"Input Options"`
    OutputOption  `group:"Output Options"`
    SmartOption   `group:"Smart Options"`
    AdvanceOption `group:"Advance Options"`
    ConfigOption  `group:"Configuration Options"`

    start  time.Time
    Config Config
}
```

```49:142:core/runner.go
// Prepare 函数准备运行环境
func (r *Runner) Prepare() bool {
    // 初始化日志工具
    if r.Quiet {
        logs.Log = logs.NewLogger(0)
        logs.Log.SetQuiet(true)
    } else {
        if r.Debug {
            logs.Log.SetLevel(logs.Debug)
        }
        logs.Log.SetFile(logFile)
        logs.Log.Init()
    }

    // 设置全局运行选项
    RunOpt = RunnerOpts{
        Delay:        r.Delay,
        HttpsDelay:   r.HttpsDelay,
        VersionLevel: setVersionLevel(r.Verbose),
        Exploit:      setExploit(r.ExploitName, r.Exploit),
        Debug:        r.Debug,
        Opsec:        r.Opsec,
    }
    
    // 设置HTTP超时和其他全局参数
    ExecuterOptions.Options.Timeout = r.Delay + r.HttpsDelay
    HttpTimeout = time.Duration(r.Delay+r.HttpsDelay) * time.Second
    Opt.PluginDebug = r.PluginDebug
    Opt.NoScan = r.NoScan
    common.NoGuess = r.NoGuess
    files.Key = []byte(r.Key)
    
    // TODO @v2 研究文件加密解密机制，了解Key的使用方式

    // 处理版本信息和配置准备
    if r.Ver {
        fmt.Println(ver)
        return false
    }

    r.PrepareConfig()
    
    // 处理排除目标
    if r.Exclude != "" {
        r.Config.Excludes = utils.ParseCIDRs(strings.Split(r.Exclude, ","))
    } else if r.ExcludeList != "" {
        ips, err := fileutils.LoadFileToSlice(r.ExcludeList)
        if err != nil {
            logs.Log.Error(err.Error())
            return false
        }
        r.Config.Excludes = utils.ParseCIDRs(ips)
    }

    if r.Config.Excludes != nil {
        RunOpt.ExcludeCIDRs = r.Config.Excludes
    }
    
    // 格式化输出处理
    if r.FormatterFilename != "" {
        LoadNeutron("")
        var formatOut string
        if r.Outputf != Default {
            formatOut = r.Outputf
        } else if r.FileOutputf != Default {
            formatOut = r.FileOutputf
        } else {
            formatOut = "color"
        }
        FormatOutput(r.FormatterFilename, r.Config.Filename, formatOut, r.Config.Filenamef, r.Filters, r.FilterOr)
        return false
    }
    
    // 打印配置信息
    if r.Printer != "" {
        printConfigs(r.Printer)
        return false
    }

    // 处理代理设置
    if len(r.Proxy) != 0 {
        var proxies []*url.URL
        for _, u := range r.Proxy {
            uri, err := url.Parse(u)
            if err != nil {
                logs.Log.Warnf("parse proxy error %s, skip proxy!", err.Error())
            } else {
                proxies = append(proxies, uri)
            }
        }
        dialer, err := proxyclient.NewClientChain(proxies)
        if err != nil {
            logs.Log.Warnf("parse proxy error %s, skip proxy!", err.Error())
        }
        neuhttp.DefaultTransport.DialContext = dialer.DialContext
        DefaultTransport.DialContext = dialer.DialContext
        ProxyDialTimeout = func(network, address string, duration time.Duration) (net.Conn, error) {
            ctx, _ := context.WithTimeout(context.Background(), duration)
            return dialer.DialContext(ctx, network, address)
        }
    }
    return true
}
```

## 加密解密与算法详解

### 文件加密实现

GOGO使用自定义加密方法保护输出的扫描结果文件。加密实现主要位于`pkg/file.go`中：

```27:41:pkg/file.go
// newFile 创建一个新的加密文件
func newFile(filename string, compress bool) (*files.File, error) {
    file, err := files.NewFile(filename, compress, true, false)
    if err != nil {
        return nil, err
    }

    var cursor int

    // 设置自定义编码器，使用XOR加密结合Deflate压缩
    file.Encoder = func(i []byte) []byte {
        bs := encode.XorEncode(encode.MustDeflateCompress(i), files.Key, cursor)
        cursor += len(bs)
        return bs
    }
    return file, nil
}
```

关键加密算法包括：

1. **XOR加密**：使用`encode.XorEncode`函数，结合`files.Key`作为密钥进行异或加密
2. **Deflate压缩**：在加密前先使用`encode.MustDeflateCompress`进行数据压缩
3. **游标偏移**：加密过程中使用游标（cursor）记录位置，实现滚动加密效果

文件解密过程在`LoadResultFile`函数中实现：

```234:250:pkg/result_data.go
func LoadResultFile(file io.Reader) interface{} {
    var data interface{}
    var err error
    // 使用files.Key进行文件解密
    content := files.DecryptFile(file, files.Key)

    content = bytes.TrimSpace(content) // 去除前后空格
    // 解析文件内容
    lines := bytes.Split(content, []byte{0x0a})
    config, err := parseConfig(lines[0])
    // ...
}
```

密钥设置在Runner.Prepare()中完成：

```78:78:core/runner.go
files.Key = []byte(r.Key)
```

从命令行参数中获取密钥，支持用户自定义密钥或使用默认密钥。

### 编码和解码工具

GOGO还提供了多种编码/解码实用工具：

```21:25:pkg/utils.go
// Decode 函数用于解码Base64+Deflate压缩的数据
func Decode(input string) []byte {
    b := encode.Base64Decode(input)
    return encode.MustDeflateDeCompress(b)
}
```

这个函数用于解码项目中预先编码的数据包，例如SMB扫描、NTLM协议测试等场景中的二进制数据。

### 模板加载机制

GOGO使用了模板系统来加载攻击模块，实现在`pkg/load_neutron.go`：

```30:60:pkg/load_neutron.go
func LoadNeutron(filename string) map[string][]*templates.Template {
    var content []byte
    if filename == "" {
        // 从内置配置加载
        return LoadTemplates(LoadConfig("neutron"))
    } else {
        if files.IsExist(filename) {
            // 从文件加载
            var err error
            content, err = ioutil.ReadFile(filename)
            if err != nil {
                iutils.Fatal(err.Error())
            }
        } else {
            // 从Base64编码字符串加载
            content = encode.Base64Decode(filename)
        }
        return LoadTemplates(content)
    }
}
```

该函数支持三种模式加载模板：
1. 内置默认模板
2. 从文件加载
3. 从Base64编码字符串直接加载

### 端口扫描算法

GOGO使用多种扫描模式，包括：

1. 默认扫描模式：直接扫描指定目标和端口
2. 智能扫描模式：使用特定探针对网段进行快速探测
3. 存活检测模式：使用ICMP或ARP协议检测主机存活状态

核心算法包括：

```241:251:core/core.go
// cidrAlived 函数用于记录存活的CIDR网段
func cidrAlived(ip string, temp *sync.Map, mask int) {
    i := net.ParseIP(ip)
    alivecidr := i.Mask(net.CIDRMask(mask, 32)).String()
    _, ok := temp.Load(alivecidr)
    if !ok {
        temp.Store(alivecidr, 1)
        logs.Log.Importantf("Found %s/%d", ip, mask)
        atomic.AddInt32(&Opt.AliveSum, 1)
    }
}
```

TODO @v2 需要进一步研究smartGenerator和generatorDispatch函数的实现，理解目标生成算法 

## 扫描策略与目标生成算法

### 目标生成器核心实现

GOGO的目标生成是扫描的核心环节，根据不同的扫描模式生成不同的目标序列。实现在`core/generator.go`：

```12:23:core/generator.go
// NewIpGenerator 创建一个新的IP生成器
func NewIpGenerator(config Config) *IpGenerator {
    var alivemap sync.Map
    gen := IpGenerator{
        alivedMap: &alivemap,
        ipProbe:   config.IpProbeList,
    }
    return &gen
}

// IpGenerator IP生成器结构体
type IpGenerator struct {
    count     int
    ch        chan string
    alivedMap *sync.Map  // 存活IP的映射表
    ipProbe   []uint     // IP探测列表
}
```

IP生成器包含三种生成模式：

```26:51:core/generator.go
// defaultIpGenerator 默认IP生成方式，遍历CIDR范围内所有IP
func (gen *IpGenerator) defaultIpGenerator(cidr *utils.CIDR) {
    for ip := range cidr.Range() {
        if ip.Ver == 6 {
            gen.ch <- "[" + ip.String() + "]"
        } else {
            gen.ch <- ip.String()
        }
    }
}

// smartIpGenerator 智能IP生成，用于C段扫描
func (gen *IpGenerator) smartIpGenerator(cidr *utils.CIDR) {
    cs, err := cidr.Split(24)
    if err != nil {
        return
    }
    ccs := make(map[string]*utils.CIDR)
    for _, c := range cs {
        ccs[c.String()] = c
    }

    for i := 0; i < 256; i++ {
        for s, c := range ccs {
            if isnotAlive(s, gen.alivedMap) {
                gen.ch <- c.Next().String()
            }
        }
    }
}
```

其中：
- `defaultIpGenerator`：简单遍历CIDR内所有IP，适用于小范围目标
- `smartIpGenerator`：智能C段扫描模式，按照/24网段生成目标
- `sSmartGenerator`：超级智能模式，适用于B段扫描，通过特定探针高效探测大范围网段

模式分发由`generatorDispatch`函数实现：

```74:92:core/generator.go
// generatorDispatch 根据不同扫描模式分发生成器
func (gen *IpGenerator) generatorDispatch(cidr *utils.CIDR, mod string) chan string {
    gen.ch = make(chan string)

    go func() {
        mask := cidr.Mask
        switch mod {
        case SMART, SUPERSMARTC:
            if mask <= 24 {
                gen.smartIpGenerator(cidr)
            }
        case SUPERSMART, SUPERSMARTB:
            if mask <= 16 {
                gen.sSmartGenerator(cidr)
            }
        default:
            gen.defaultIpGenerator(cidr)
        }
        close(gen.ch)
    }()
    return gen.ch
}
```

### 目标-端口生成策略

目标与端口组合由`TargetGenerator`负责：

```108:131:core/generator.go
// TargetGenerator 目标生成器，将IP与端口结合
type TargetGenerator struct {
    count       int
    spray       bool               // 是否启用端口喷洒模式
    ch          chan targetConfig
    hostsMap    map[string][]string  // 主机映射表
    ipGenerator *IpGenerator         // IP生成器
}

// genFromDefault 默认生成器：先遍历IP，然后遍历端口（适合IP少，端口多的情况）
func (gen *TargetGenerator) genFromDefault(cidrs utils.CIDRs, portlist []string) {
    for _, cidr := range cidrs {
        tmpalived := Opt.AliveSum
        ch := gen.ipGenerator.generatorDispatch(cidr, Default)
        for ip := range ch {
            for _, port := range portlist {
                gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}
                if engine.RunOpt.Sum%65535 == 65534 {
                    Log.Importantf("Current processing %s:%s, number: %d", ip, port, engine.RunOpt.Sum)
                }
            }
        }
        if cidr.Count() > 1 {
            Log.Importantf("Scanned %s with %d ports, found %d ports", cidr.String(), len(portlist), Opt.AliveSum-tmpalived)
        }
        syncFile()
    }
}
```

端口喷洒模式更适合扫描大网段：

```133:160:core/generator.go
// genFromSpray 端口喷洒模式：先遍历端口，然后遍历IP（适合IP多，扫描特定端口的情况）
func (gen *TargetGenerator) genFromSpray(cidrs utils.CIDRs, portlist []string) {
    var tmpPorts []string
    for _, port := range portlist {
        lastalive := Opt.AliveSum

        for _, cidr := range cidrs {
            ch := gen.ipGenerator.generatorDispatch(cidr, Default)
            for ip := range ch {
                gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}
            }
            syncFile()
        }

        tmpPorts = append(tmpPorts, port)
        // 减少-l 模式下的日志输出, 每处理了100个端口输出一次
        if Opt.AliveSum-lastalive > 0 {
            if len(tmpPorts) > 5 {
                Log.Importantf("Processed Port: %s - %s, found %d ports", tmpPorts[0], tmpPorts[len(tmpPorts)-1], Opt.AliveSum-lastalive)
            } else {
                Log.Importantf("Processed Port: %s, found %d ports", strings.Join(tmpPorts, ","), Opt.AliveSum-lastalive)
            }
            tmpPorts = []string{}
        }
    }
}
```

### 扫描模式算法

GOGO支持多种扫描模式，针对不同场景优化：

```95:184:core/core.go
// SmartMod 是智能扫描模式，用于对整个网段进行探测
func SmartMod(target *utils.CIDR, config Config) {
    // 初始化mask
    var mask int
    switch config.Mod {
    case SUPERSMART, SUPERSMARTB:
        // sc, ss - B段模式
        if target.Mask > 16 {
            logs.Log.Error(target.String() + " is less than B class, skipped")
        }
        mask = 16
        if config.PortProbe == Default {
            config.PortProbeList = DefaultSuperSmartPortProbe
        }
    default:
        // s - C段模式
        if target.Mask > 24 {
            logs.Log.Error(target.String() + " is less than C class, skipped")
            return
        }
        mask = 24
        if config.PortProbe == Default {
            config.PortProbeList = DefaultSmartPortProbe
        }
    }
    // 预估扫描时间
    spended := guessSmartTime(target, config)
    logs.Log.Importantf("Spraying %s with %s, Estimated to take %d seconds", target, config.Mod, spended)
    var wg sync.WaitGroup

    targetGen := NewTargetGenerator(config)
    temp := targetGen.ipGenerator.alivedMap

    // 输出启发式扫描探针配置
    probeconfig := fmt.Sprintf("Smart port probes: %s ", strings.Join(config.PortProbeList, ","))
    if config.IsBSmart() {
        probeconfig += ", Smart IP probes: " + fmt.Sprintf("%v", config.IpProbeList)
    }
    logs.Log.Important(probeconfig)

    // 生成智能扫描目标
    tcChannel := targetGen.smartGenerator(target, config.PortProbeList, config.Mod)

    // 使用工作池处理扫描任务
    scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
        tc := i.(targetConfig)
        result := NewResult(tc.ip, tc.port)
        result.SmartProbe = true
        engine.Dispatch(result)

        if result.Open {
            logs.Log.Debug("cidr scan , " + result.String())
            cidrAlived(result.Ip, temp, mask)
        } else if result.Error != "" {
            logs.Log.Debugf("%s stat: %s, errmsg: %s", result.GetTarget(), PortStat[result.ErrStat], result.Error)
        }
        wg.Done()
    })
    defer scanPool.Release()
    
    // 提交扫描任务
    for t := range tcChannel {
        wg.Add(1)
        _ = scanPool.Invoke(t)
    }
    wg.Wait()

    // 处理扫描结果
    var iplist utils.CIDRs
    temp.Range(func(ip, _ interface{}) bool {
        iplist = append(iplist, utils.NewCIDR(ip.(string), mask))
        return true
    })

    // 网段排序
    if len(iplist) > 0 {
        sort.Sort(iplist)
    } else {
        return
    }

    // 输出扫描结果
    logs.Log.Importantf("Smart scan: %s finished, found %d alive cidrs", target, len(iplist))
    if config.IsBSmart() {
        WriteSmartResult(config.SmartBFile, target.String(), iplist.Strings())
    }
    if config.IsCSmart() {
        WriteSmartResult(config.SmartCFile, target.String(), iplist.Strings())
    }

    // 决定是否继续深入扫描
    if Opt.NoScan || config.Mod == SUPERSMARTC {
        // -no 被设置的时候停止后续扫描
        return
    }
    createDeclineScan(iplist, config)
}
```

关键算法`cidrAlived`用于标记存活网段：

```241:251:core/core.go
// cidrAlived 函数用于记录存活的CIDR网段
func cidrAlived(ip string, temp *sync.Map, mask int) {
    i := net.ParseIP(ip)
    alivecidr := i.Mask(net.CIDRMask(mask, 32)).String()
    _, ok := temp.Load(alivecidr)
    if !ok {
        temp.Store(alivecidr, 1)
        logs.Log.Importantf("Found %s/%d", ip, mask)
        atomic.AddInt32(&Opt.AliveSum, 1)
    }
}
```

扫描时间估算函数：

```177:201:core/init.go
// guessTime 用于估算扫描时间，提供用户参考
func guessTime(targets interface{}, portcount, thread int) int {
    ipcount := 0

    switch targets.(type) {
    case utils.CIDRs:
        for _, cidr := range targets.(utils.CIDRs) {
            ipcount += cidr.Count()
        }
    case utils.CIDR:
        ipcount += targets.(*utils.CIDR).Count()
    case parsers.GOGOResults:
        ipcount = len(targets.(parsers.GOGOResults))
        portcount = 1
    default:
    }

    // 估算公式：(端口数*IP数/线程数)*4 + 4秒
    return (portcount*ipcount/thread)*4 + 4
}
``` 

## 协议分析与安全扫描实现

GOGO支持多种协议和安全扫描功能，实现在engine目录下的各个模块中。

### 核心调度模块

`Dispatch.go`是扫描引擎的核心调度模块，根据端口或服务类型选择合适的扫描器：

```29:82:engine/Dispatch.go
// Dispatch 函数是扫描引擎的核心调度函数，根据端口和服务类型选择合适的扫描模块
func Dispatch(result *pkg.Result) {
    defer func() {
        if err := recover(); err != nil {
            logs.Log.Errorf("scan %s unexcept error, %v", result.GetTarget(), err)
            panic(err)
        }
    }()
    atomic.AddInt32(&RunOpt.Sum, 1)
    if RunOpt.ExcludeCIDRs != nil && RunOpt.ExcludeCIDRs.ContainsString(result.Ip) {
        logs.Log.Debug("exclude ip: " + result.Ip)
        return
    }
    
    // 根据端口选择不同的扫描模块
    if result.Port == "137" || result.Port == "nbt" {
        NBTScan(result)
        return
    } else if result.Port == "135" || result.Port == "wmi" {
        WMIScan(result)
        return
    } else if result.Port == "oxid" {
        OXIDScan(result)
        return
    } else if result.Port == "icmp" || result.Port == "ping" {
        ICMPScan(result)
        return
    } else if result.Port == "snmp" || result.Port == "161" {
        SNMPScan(result)
        return
    } else if result.Port == "445" || result.Port == "smb" {
        SMBScan(result)
        if RunOpt.Exploit == "ms17010" {
            MS17010Scan(result)
        } else if RunOpt.Exploit == "smbghost" || RunOpt.Exploit == "cve-2020-0796" {
            SMBGhostScan(result)
        } else if RunOpt.Exploit == "auto" || RunOpt.Exploit == "smb" {
            MS17010Scan(result)
            SMBGhostScan(result)
        }
        return
    } else if result.Port == "mssqlntlm" {
        MSSqlScan(result)
        return
    } else if result.Port == "winrm" {
        WinrmScan(result)
        return
    } else {
        InitScan(result)
    }
}
```

### HTTP/HTTPS协议处理

HTTP扫描是最常用的扫描方式，通过多种策略识别服务：

```13:62:engine/httpScan.go
// InitScan 是初始扫描函数，对目标进行基础扫描
func InitScan(result *pkg.Result) {
    var bs []byte
    target := result.GetTarget()
    defer func() {
        // 如果进行了各种探测依旧为tcp协议, 则收集tcp端口状态
        if result.Protocol == "tcp" {
            if result.Err != nil {
                result.Error = result.Err.Error()
                if RunOpt.Debug {
                    result.ErrStat = handleError(result.Err)
                }
            }
        }
    }()

    // 创建TCP连接
    conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
    if err != nil {
        result.Err = err
        return
    }
    defer conn.Close()
    result.Open = true

    // 启发式扫描探测直接返回不需要后续处理
    if result.SmartProbe {
        return
    }
    result.Status = "open"

    // 尝试读取数据
    bs, err = conn.Read(RunOpt.Delay)
    if err != nil {
        // 如果直接读取失败，尝试发送HTTP请求
        senddataStr := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", result.Uri, target)
        bs, err = conn.Request([]byte(senddataStr), pkg.DefaultMaxSize)
        if err != nil {
            result.Err = err
        }
    }
    pkg.CollectSocketResponse(result, bs)

    // 处理特殊情况：HTTP/HTTPS协议识别
    if result.Status == "400" || result.Protocol == "tcp" || (strings.HasPrefix(result.Status, "3") && bytes.Contains(result.Content, []byte("location: https"))) {
        systemHttp(result, "https")
    } else if strings.HasPrefix(result.Status, "3") {
        systemHttp(result, "http")
    }

    return
}
```

HTTP强制跳转处理与协议识别：

```63:113:engine/httpScan.go
// systemHttp 使用net/http进行带redirect的请求
func systemHttp(result *pkg.Result, scheme string) {
    // 如果是400或者不可识别协议,则使用https
    target := scheme + "://" + result.GetTarget()
    conn := result.GetHttpConn(RunOpt.Delay + RunOpt.HttpsDelay)
    resp, err := pkg.HTTPGet(conn, target)
    if err != nil {
        // 有可能存在漏网之鱼, 是tls服务, 但tls的第一个响应为30x, 并30x的目的地址不可达或超时. 则会报错.
        result.Error = err.Error()
        logs.Log.Debugf("request %s , %s ", target, err.Error())
        if result.IsHttp {
            noRedirectHttp(result, target)
        }
        return
    }
    logs.Log.Debugf("request %s , %d ", target, resp.StatusCode)
    if resp.TLS != nil {
        if result.Status == "400" {
            // socket中得到的状态为400, 且存在tls的情况下
            result.Protocol = "https"
        } else if resp.StatusCode == 400 {
            // 虽然获取到了tls, 但是状态码为400, 则根据scheme取反
            // 某些中间件会自动打开tls端口, 但是证书为空, 返回400
            if scheme == "http" {
                result.Protocol = "https"
            } else {
                result.Protocol = "http"
            }
        } else if scheme == "http" && resp.Request.Response != nil && resp.Request.URL.Scheme == "https" {
            // 去掉通过302 http跳转到https导致可能存在的误判
            result.Protocol = "http"
        } else {
            result.Protocol = scheme
        }

        pkg.CollectTLS(result, resp)
    } else if resp.Request.Response != nil && resp.Request.Response.TLS != nil {
        // 一种相对罕见的情况, 从https页面30x跳转到http页面. 则判断tls
        result.Protocol = "https"

        pkg.CollectTLS(result, resp.Request.Response)
    } else {
        result.Protocol = "http"
    }

    result.Error = ""
    pkg.CollectHttpResponse(result, resp)
    return
}
```

### Windows协议与安全扫描

#### SMB协议实现

SMB扫描用于检测Windows文件共享服务，支持识别SMBv1和SMBv2协议：

```26:131:engine/smbScan.go
// SMBScan 扫描SMB服务，识别版本和主机信息
func SMBScan(result *pkg.Result) {
    result.Port = "445"
    target := result.GetTarget()
    var err error
    var ret []byte
    //ff534d42 SMBv1的标示
    //fe534d42 SMBv2的标示
    //先发送探测SMBv1的payload，不支持的SMBv1的时候返回为空，然后尝试发送SMBv2的探测数据包
    ret, err = smb1Scan(target)
    if err != nil && err.Error() == "conn failed" {
        return
    }

    if ret == nil {
        result.Open = true
        if ret, err = smb2Scan(target); ret != nil {
            result.Status = "SMB2"
        } else {
            result.Protocol = "tcp"
            result.Status = "tcp"
            return
        }
    } else {
        result.Open = true
        result.Status = "SMB1"
    }

    result.Protocol = "smb"
    result.AddNTLMInfo(iutils.ToStringMap(ntlmssp.NTLMInfo(ret)), "smb")
}
```

#### NTLM信息收集

NTLM是Windows网络认证协议，可提供大量主机信息：

```158:167:pkg/result.go
// AddNTLMInfo 添加NTLM认证信息
func (result *Result) AddNTLMInfo(m map[string]string, t string) {
    if m == nil {
        return
    }
    result.Title = m["MsvAvNbDomainName"] + "/" + m["MsvAvNbComputerName"]
    result.Host = strings.Trim(m["MsvAvDnsDomainName"], "\x00") + "/" + m["MsvAvDnsComputerName"]
    result.AddFramework(common.NewFrameworkWithVersion(t, common.FrameFromDefault, m["Version"]))
}
```

从NTLM响应中提取的信息包括：
- 域名称 (MsvAvNbDomainName)
- 计算机名 (MsvAvNbComputerName)
- DNS域名 (MsvAvDnsDomainName)
- DNS计算机名 (MsvAvDnsComputerName)
- 系统版本信息 (Version)

#### MS17-010漏洞扫描

MS17-010是著名的永恒之蓝漏洞，扫描实现如下：

```18:99:engine/ms17010Scan.go
// MS17010Scan 扫描永恒之蓝漏洞(MS17-010)
func MS17010Scan(result *Result) {
    if RunOpt.Opsec {
        logs.Log.Debugf("opsec!!! skip MS-17010 plugin")
        return
    }
    // connecting to a host in LAN if reachable should be very quick
    result.Port = "445"
    target := result.GetTarget()
    conn, err := NewSocket("tcp", target, RunOpt.Delay)
    if err != nil {
        result.Error = err.Error()
        return
    }
    result.Protocol = "smb"
    result.Open = true
    defer conn.Close()

    // 协议协商
    reply, err := conn.Request(negotiateProtocolRequest, 1024)
    n := len(reply)
    if err != nil || len(reply) < 36 {
        result.Error = err.Error()
        return
    }
    if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
        // status != 0
        return
    }

    // 会话建立
    reply, err = conn.Request(sessionSetupRequest, 1024)
    n = len(reply)
    if err != nil || n < 36 {
        result.Error = err.Error()
        return
    }

    if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
        // status != 0
        return
    }

    // 提取操作系统信息
    var os string
    sessionSetupResponse := reply[36:n]
    if wordCount := sessionSetupResponse[0]; wordCount != 0 {
        // find byte count
        byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
        if n != int(byteCount)+45 {
        } else {
            // two continous null bytes indicates end of a unicode string
            for i := 10; i < len(sessionSetupResponse)-1; i++ {
                if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
                    os = string(sessionSetupResponse[10:i])
                    break
                }
            }
        }
    }

    // 提取会话信息
    userID := reply[32:34]
    treeConnectRequest[32] = userID[0]
    treeConnectRequest[33] = userID[1]

    // 连接SMB共享
    reply, err = conn.Request(treeConnectRequest, 1024)
    n = len(reply)
    if err != nil || n < 36 {
        result.Error = err.Error()
        return
    }

    // 提取树ID
    treeID := reply[28:30]
    transNamedPipeRequest[28] = treeID[0]
    transNamedPipeRequest[29] = treeID[1]
    transNamedPipeRequest[32] = userID[0]
    transNamedPipeRequest[33] = userID[1]
}
```

#### SMBGhost漏洞检测

SMBGhost (CVE-2020-0796) 漏洞扫描实现简洁：

```12:29:engine/smbGhostScan.go
// SMBGhostScan 扫描SMBGhost漏洞(CVE-2020-0796)
func SMBGhostScan(result *pkg.Result) {
    target := result.GetTarget()
    conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
    if err != nil {
        return
    }
    defer conn.Close()
    content, err := conn.Request(sgpkt, 1024)
    if err != nil {
        return
    }
    if len(content) < 76 {
        return
    }
    // 检查SMB协议响应中的特征字节
    if bytes.Equal(content[72:74], []byte{0x11, 0x03}) && bytes.Equal(content[74:76], []byte{0x02, 0x00}) {
        result.AddVuln(&common.Vuln{Name: "SMBGHOST", SeverityLevel: common.SeverityCRITICAL})
    }
}
```

### WMI/OXID协议实现

Windows管理规范实现(WMI)扫描：

```12:33:engine/wmiScan.go
// WMIScan 扫描WMI服务
func WMIScan(result *pkg.Result) {
    result.Port = "135"
    target := result.GetTarget()
    conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
    if err != nil {
        return
    }
    defer conn.Close()

    result.Open = true
    ret, err := conn.Request(data, 4096)
    if err != nil {
        return
    }

    // 从响应中查找NTLM信息
    if bytes.Index(ret, []byte("NTLMSSP")) != -1 {
        result.Protocol = "wmi"
        result.Status = "wmi"
        result.AddNTLMInfo(iutils.ToStringMap(ntlmssp.NTLMInfo(ret)), "wmi")
    }
}
```

### NetBIOS协议实现

NetBIOS扫描可获取Windows主机名和工作组信息：

```54:132:engine/nbtScan.go
// NBTScan 扫描NetBIOS服务，获取主机信息
func NBTScan(result *pkg.Result) {
    var Share bool = false
    var DC bool = false
    result.Protocol = "udp"
    result.Port = "137"
    target := result.GetTarget()

    conn, err := pkg.NewSocket("udp", target, RunOpt.Delay*2)
    if err != nil {
        return
    }
    defer conn.Close()

    reply, err := conn.Request(nbtdata, 1024)
    if err != nil {
        return
    }

    result.Open = true
    if len(reply) <= 58 {
        return
    }

    // 解析NetBIOS名称响应
    num, err := Byte2Int(reply[56:57])
    if err != nil {
        result.Error = err.Error()
        return
    }

    var name, group, unique string
    var flag_bit []byte
    data := reply[57:]
    for i := 0; i < num; i++ {
        name = string(data[18*i : 18*i+15])
        flag_bit = data[18*i+15 : 18*i+16]
        
        if string(flag_bit) == "\x00" {
            name_flags := data[18*i+16 : 18*i+18]
            num, _ := Byte2Int(name_flags[0:1])
            if num >= 80 {
                group = strings.Trim(name, " ")
            } else {
                unique = name
                if string(flag_bit) == "\x20" {
                    Share = true
                }
            }
        } else {
            if _, ok := groupNames[string(flag_bit)]; ok {
                if string(flag_bit) == "\x1C" {
                    DC = true
                }
            } else if _, ok := uniqueNames[string(flag_bit)]; ok {
                if string(flag_bit) == "\x20" {
                    Share = true
                }
            }
        }
    }

    // 设置扫描结果
    msg := group + "\\" + unique
    msg = strings.Replace(msg, "\x00", "", -1)
    result.Status = ""
    if Share {
        result.Status += "sharing"
    }
    if DC {
        result.Status += "DC"
    }
    result.Host = msg
    result.Protocol = "netbios"
    return
}
``` 

## 学习流程与使用指南

### 学习路径

要全面理解GOGO扫描器的工作原理和使用方法，建议按照以下流程学习：

1. **核心概念与项目结构**
   - 了解项目的整体架构和文件组织
   - 掌握基本的扫描模式和参数配置

2. **命令行接口学习**
   - 从`cmd/cmd.go`入手理解命令行参数解析
   - 了解`Runner`结构及其初始化过程
   - 掌握配置文件的加载和参数合并

3. **扫描模式详解**
   - 学习默认扫描模式`DefaultMod`的工作原理
   - 理解智能扫描模式`SmartMod`的优化策略
   - 掌握存活检测模式`AliveMod`的实现方式
   - 掌握端口喷洒与IP遍历的区别和适用场景

4. **目标生成算法**
   - 理解CIDR解析和IP范围生成
   - 学习不同扫描模式下的目标生成策略
   - 掌握线程池和协程调度机制

5. **协议扫描实现**
   - 学习HTTP/HTTPS服务的识别与分析
   - 理解SMB、WMI等Windows协议的扫描实现
   - 掌握MS17-010、SMBGhost等漏洞检测原理

6. **结果处理与输出**
   - 理解扫描结果的存储格式
   - 掌握结果过滤和格式化输出
   - 学习文件加密和解密机制

### 常用扫描命令示例

#### 基本扫描

扫描单个IP的所有常用端口：
```bash
./gogo -ip 192.168.1.1
```

扫描特定端口：
```bash
./gogo -ip 192.168.1.1 -p 80,443,8080
```

扫描IP段：
```bash
./gogo -ip 192.168.1.0/24
```

#### 智能扫描模式

C段智能扫描：
```bash
./gogo -ip 192.168.1.0/24 -m s
```

B段智能扫描：
```bash
./gogo -ip 192.168.0.0/16 -m ss
```

指定扫描端口探针：
```bash
./gogo -ip 192.168.1.0/24 -m s -pp 80,443,8080
```

#### 输出控制

指定输出文件：
```bash
./gogo -ip 192.168.1.0/24 -o result.json
```

指定输出格式：
```bash
./gogo -ip 192.168.1.0/24 -of json
```

#### 漏洞检测

启用MS17-010漏洞检测：
```bash
./gogo -ip 192.168.1.0/24 -e ms17010
```

启用SMBGhost漏洞检测：
```bash
./gogo -ip 192.168.1.0/24 -e smbghost
```

启用全部漏洞检测：
```bash
./gogo -ip 192.168.1.0/24 -e auto
```

### 核心数据结构

#### Result结构

```24:42:pkg/result.go
// Result 结构存储扫描结果信息
type Result struct {
    *parsers.GOGOResult
    HttpHosts   []string `json:"-"`
    CurrentHost string   `json:"-"`

    IsHttp     bool              `json:"-"`
    Filtered   bool              `json:"-"`
    Open       bool              `json:"-"`
    SmartProbe bool              `json:"-"`
    TcpConn    *net.Conn         `json:"-"`
    HttpConn   *http.Client      `json:"-"`
    Httpresp   *parsers.Response `json:"-"`
    HasTitle   bool              `json:"-"`
    Err        error             `json:"-"`
    Error      string            `json:"-"`
    ErrStat    int               `json:"-"`
    Content    []byte            `json:"-"`
}
```

#### Config结构

```28:68:pkg/config.go
// Config 结构包含所有配置选项
type Config struct {
    *parsers.GOGOConfig
    // ip
    CIDRs    utils.CIDRs `json:"-"`
    Excludes utils.CIDRs `json:"-"`
    // port and probe
    //Ports         string   `json:"ports"` // 预设字符串
    PortList      []string `json:"-"` // 处理完的端口列表
    PortProbe     string   `json:"-"` // 启发式扫描预设探针
    PortProbeList []string `json:"-"` // 启发式扫描预设探针
    IpProbe       string   `json:"-"`
    IpProbeList   []uint   `json:"-"`

    // file
    IsListInput bool `json:"-"` // 从标准输入中读
    IsJsonInput bool `json:"-"` // 从标准输入中读
    NoSpray     bool `json:"-"`
    Compress    bool `json:"-"`

    // output
    FilePath       string              `json:"-"`
    Filename       string              `json:"-"`
    SmartBFilename string              `json:"-"`
    SmartCFilename string              `json:"-"`
    AlivedFilename string              `json:"-"`
    File           *files.File         `json:"-"`
    SmartBFile     *files.File         `json:"-"`
    SmartCFile     *files.File         `json:"-"`
    AliveFile      *files.File         `json:"-"`
    Tee            bool                `json:"-"`
    Outputf        string              `json:"-"`
    FileOutputf    string              `json:"-"`
    Filenamef      string              `json:"-"`
    Results        parsers.GOGOResults `json:"-"` // json反序列化后的,保存在内存中
    HostsMap       map[string][]string `json:"-"` // host映射表
    Filters        []string            `json:"-"`
    FilterOr       bool                `json:"-"`
    OutputFilters  [][]string          `json:"-"`
}
```

## 总结

GOGO是一个功能丰富、架构合理的高效网络扫描工具，具有以下特点：

1. **多种扫描模式**：支持默认扫描、智能扫描、存活检测等多种模式，适应不同场景需求

2. **高效的目标生成算法**：通过智能分解大型网段，结合特定探针进行高效探测

3. **全面的协议支持**：支持HTTP/HTTPS、SMB、WMI、NetBIOS等多种协议的扫描和指纹识别

4. **安全漏洞检测**：内置MS17-010、SMBGhost等漏洞检测能力

5. **灵活的输出控制**：支持多种输出格式，方便与其他工具集成

6. **安全性考虑**：支持OPSEC安全模式，避免触发安全设备告警

通过深入学习GOGO的源码，可以全面了解现代网络扫描工具的实现原理和最佳实践，为网络安全评估和渗透测试提供有力工具。

## 待研究问题

1. TODO @v2 文件加密解密机制的深入分析，理解Key的生成和使用方式

2. TODO @v2 smartGenerator和generatorDispatch函数的实现细节，优化目标生成算法

3. TODO @v2 NTLM协议分析和信息提取细节，深入理解Windows认证机制

4. TODO @v2 指纹识别的实现机制，改进服务识别准确率 