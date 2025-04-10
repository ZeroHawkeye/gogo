package engine

import (
	"sync/atomic"

	"github.com/chainreactors/utils"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/iutils"
)

// RunnerOpts 运行时选项结构体，保存全局配置参数
type RunnerOpts struct {
	Sum          int32      // 已处理的目标总数，用于统计和进度显示
	Exploit      string     // 漏洞利用选项，控制是否执行漏洞扫描及扫描类型
	VersionLevel int        // 版本信息收集级别，级别越高收集信息越详细
	Delay        int        // 基础超时时间(秒)，影响扫描速度和准确性的平衡
	HttpsDelay   int        // HTTPS额外超时时间(秒)，HTTPS服务通常需要更长的超时
	ScanFilters  [][]string // 扫描过滤器，用于过滤不需要深度扫描的目标
	//SuffixStr    string
	Debug        bool        // 调试模式，启用时会输出更详细的日志
	Opsec        bool        // 安全操作模式(Operation Security)，避免触发IDS/IPS
	ExcludeCIDRs utils.CIDRs // 排除的CIDR网段，这些网段不会被扫描
}

var (
	RunOpt RunnerOpts // 全局运行时配置实例
)

// Dispatch 是扫描引擎的核心调度函数，根据端口和服务类型选择合适的扫描模块
// 这个函数接收一个扫描结果对象，根据其端口决定使用哪种扫描方式
// 整个扫描过程分为四个主要阶段：特定端口协议扫描、指纹识别、信息收集和漏洞扫描
func Dispatch(result *pkg.Result) {
	// 异常处理，防止单个扫描任务的异常影响整个扫描进程
	defer func() {
		if err := recover(); err != nil {
			logs.Log.Errorf("scan %s unexcept error, %v", result.GetTarget(), err)
			panic(err)
		}
	}()

	// 增加已处理目标计数，用于统计和进度显示
	atomic.AddInt32(&RunOpt.Sum, 1)

	// 检查目标是否在排除列表中，如果是则跳过扫描
	if RunOpt.ExcludeCIDRs != nil && RunOpt.ExcludeCIDRs.ContainsString(result.Ip) {
		logs.Log.Debug("exclude ip: " + result.Ip)
		return
	}

	// ==================== 第一阶段：特定端口协议扫描 ====================
	// 按照端口号分配不同的专用扫描模块
	// 这些特定端口通常有专门的扫描模块进行处理
	if result.Port == "137" || result.Port == "nbt" {
		// NetBIOS名称服务扫描
		// 用于获取Windows主机名、域名和工作组信息
		NBTScan(result)
		return
	} else if result.Port == "135" || result.Port == "wmi" {
		// Windows RPC服务扫描
		// Windows管理规范实现(WMI)是Windows远程管理的基础
		WMIScan(result)
		return
	} else if result.Port == "oxid" {
		// DCOM对象解析器扫描
		// 用于获取目标主机的网络接口信息
		OXIDScan(result)
		return
	} else if result.Port == "icmp" || result.Port == "ping" {
		// ICMP协议扫描
		// 用于检测主机存活状态
		ICMPScan(result)
		return
	} else if result.Port == "snmp" || result.Port == "161" {
		// 简单网络管理协议扫描
		// 可获取设备配置、系统信息等
		SNMPScan(result)
		return
	} else if result.Port == "445" || result.Port == "smb" {
		// SMB文件共享协议扫描
		// Windows文件共享的核心协议
		SMBScan(result)

		// 根据配置的Exploit参数选择漏洞扫描模块
		if RunOpt.Exploit == "ms17010" {
			// 永恒之蓝漏洞扫描 (MS17-010)
			// 这是一个高危的SMBv1漏洞，曾导致全球范围的勒索攻击
			MS17010Scan(result)
		} else if RunOpt.Exploit == "smbghost" || RunOpt.Exploit == "cve-2020-0796" {
			// SMBGhost漏洞扫描 (CVE-2020-0796)
			// SMBv3的压缩机制中的漏洞，可导致远程代码执行
			SMBGhostScan(result)
		} else if RunOpt.Exploit == "auto" || RunOpt.Exploit == "smb" {
			// 自动模式：扫描所有SMB相关漏洞
			// 按照危险程度顺序依次扫描
			MS17010Scan(result)
			SMBGhostScan(result)
		}
		return
	} else if result.Port == "mssqlntlm" {
		// MS SQL Server NTLM认证扫描
		// 用于获取SQL Server的版本和主机信息
		MSSqlScan(result)
		return
	} else if result.Port == "winrm" {
		// Windows远程管理服务扫描
		// 基于WS-Management协议的Windows远程管理接口
		WinrmScan(result)
		return
	} else {
		// 针对未知端口的通用扫描
		// 尝试建立连接并识别服务类型
		InitScan(result)
	}

	// 如果端口未开放或者是启发式探针，直接返回，不进行后续扫描
	// 启发式探针主要用于快速确认端口是否开放，不需要进行深入扫描
	if !result.Open || result.SmartProbe {
		return
	}

	// ==================== 第二阶段：指纹识别 ====================
	// 根据协议类型选择合适的指纹识别方式
	if result.IsHttp {
		// HTTP服务指纹识别
		// 分析HTTP响应头、网页内容等识别Web服务器和应用
		HTTPFingerScan(result)
	} else {
		// 非HTTP服务指纹识别
		// 分析非HTTP协议的响应特征，识别服务类型和版本
		SocketFingerScan(result)
	}

	// 过滤检查：应用扫描过滤规则
	// 如果结果被过滤则跳过后续深度扫描，提高效率
	if result.Filter(RunOpt.ScanFilters) {
		return
	}

	// ==================== 第三阶段：信息收集 ====================
	// 主动信息收集，根据版本级别选择不同的收集策略
	if RunOpt.VersionLevel > 0 && result.IsHttp {
		// 对HTTP服务进行深度分析，版本级别大于0时启用
		if result.HttpHosts != nil {
			// 主机名扫描：测试不同的主机名访问情况
			// 用于发现虚拟主机配置和多站点部署
			hostScan(result)
		}

		// favicon指纹扫描：分析网站图标的hash特征
		// 许多Web应用有特定的favicon，可用于识别应用类型
		FaviconScan(result)

		// 404页面分析：检查自定义404页面的特征
		// 许多Web应用有特定的404页面，可用于辅助识别
		if result.Status != "404" {
			NotFoundScan(result)
		}
	} else {
		// 对于非HTTP服务或版本级别为0的情况
		if !result.IsHttp && result.NoFramework() {
			// 通过默认端口号猜测服务类型
			// 这是一种基于经验的启发式判断，不具备高准确性
			result.GuessFramework()
		}
	}

	// ==================== 第四阶段：漏洞扫描 ====================
	// 如果配置了漏洞利用选项(非none)，则进行漏洞扫描
	if RunOpt.Exploit != "none" {
		// 使用neutron引擎扫描漏洞
		// neutron是内置的漏洞扫描引擎，基于模板匹配原理
		NeutronScan(result.GetHostBaseURL(), result)
	}

	// 最终处理：对标题进行ASCII编码处理，确保输出正常
	// 这是为了处理可能含有非ASCII字符的标题，避免显示乱码
	result.Title = iutils.AsciiEncode(result.Title)
	return
}
