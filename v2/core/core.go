package core

import (
	"fmt"
	"net"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/gogo/v2/engine"

	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/panjf2000/ants/v2"
)

// targetConfig 目标配置结构体，包含扫描目标的基本信息
type targetConfig struct {
	ip      string            // 目标IP地址
	port    string            // 目标端口
	hosts   []string          // 目标主机名列表
	fingers common.Frameworks // 指纹信息
}

// NewResult 创建一个新的扫描结果对象
// 将目标配置信息转换为Result结构体，用于后续处理
func (tc *targetConfig) NewResult() *Result {
	result := NewResult(tc.ip, tc.port)
	// 如果有主机名信息，则设置到结果中
	if tc.hosts != nil {
		if len(tc.hosts) == 1 {
			result.CurrentHost = tc.hosts[0]
		}
		result.HttpHosts = tc.hosts
	}
	// 如果有指纹信息，则设置到结果中
	if tc.fingers != nil {
		result.Frameworks = tc.fingers
	}

	//if plugin.RunOpt.SuffixStr != "" && !strings.HasPrefix(plugin.RunOpt.SuffixStr, "/") {
	//	result.Uri = "/" + plugin.RunOpt.SuffixStr
	//}
	return result
}

// DefaultMod 默认扫描模式：直接扫描指定的目标和端口
// 适用于目标数量较少，需要全面扫描的场景
// 这是最基本的扫描模式，会对所有指定目标的所有指定端口进行扫描
func DefaultMod(targets interface{}, config Config) {
	// 输出预估时间，基于目标数量、端口数量和线程数计算
	logs.Log.Importantf("Default Scan is expected to take %d seconds", guessTime(targets, len(config.PortList), config.Threads))
	var wgs sync.WaitGroup

	// 创建目标生成器，用于生成扫描目标
	targetGen := NewTargetGenerator(config)
	// 生成扫描目标通道
	targetCh := targetGen.generatorDispatch(targets, config.PortList)

	// 创建扫描工作池，使用ants库实现高效协程管理
	// 工作池大小由config.Threads决定，这决定了并发扫描的数量
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		defer wgs.Done()
		tc := i.(targetConfig)

		// 创建扫描结果对象
		result := tc.NewResult()

		// 分发到具体的扫描模块处理
		// Dispatch是核心调度函数，根据端口和协议选择合适的扫描方式
		engine.Dispatch(result)

		if result.Open {
			// 记录存活目标数量
			atomic.AddInt32(&Opt.AliveSum, 1)

			if !result.Filtered {
				// 如果未被过滤，应用输出过滤规则
				result.Filter(config.OutputFilters)
			}

			if result.Filtered {
				// 被过滤的结果仅输出到调试日志
				logs.Log.Debug("[filtered] " + output(result, config.Outputf))
			} else {
				// 未被过滤的结果输出到控制台
				logs.Log.Console(output(result, config.Outputf))
			}

			// 文件输出处理
			if config.File != nil {
				if !config.File.Initialized {
					logs.Log.Important("init file: " + config.File.Filename)
				}
				// 将结果安全写入文件
				config.File.SafeWrite(output(result, config.FileOutputf))
			}
		} else if result.Error != "" {
			// 记录扫描错误信息到调试日志
			logs.Log.Debugf("%s stat: %s, errmsg: %s", result.GetTarget(), PortStat[result.ErrStat], result.Error)
		}
	}, ants.WithPanicHandler(func(err interface{}) {
		// 异常处理，捕获工作协程中的panic
		if Opt.PluginDebug == true {
			debug.PrintStack()
		}
	}))
	defer scanPool.Release()

	// 提交扫描任务到工作池
	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	// 等待所有扫描任务完成
	wgs.Wait()
}

// SmartMod 智能扫描模式：使用特定探针对网段进行高效扫描
// 适用于大型网段扫描，通过探测器快速定位存活主机
// 这是扫描大规模网络的推荐模式，可以大幅减少无效扫描
func SmartMod(target *utils.CIDR, config Config) {
	// 根据扫描模式确定子网掩码，决定扫描精度
	var mask int
	switch config.Mod {
	case SUPERSMART, SUPERSMARTB:
		// B段扫描模式 - 用于/16子网
		if target.Mask > 16 {
			logs.Log.Error(target.String() + " is less than B class, skipped")
		}
		mask = 16
		// 如果未指定端口探针，使用默认的超级智能模式端口探针
		if config.PortProbe == Default {
			config.PortProbeList = DefaultSuperSmartPortProbe
		}
	default:
		// C段扫描模式 - 用于/24子网
		if target.Mask > 24 {
			logs.Log.Error(target.String() + " is less than C class, skipped")
			return
		}
		mask = 24
		// 如果未指定端口探针，使用默认的智能模式端口探针
		if config.PortProbe == Default {
			config.PortProbeList = DefaultSmartPortProbe
		}
	}

	// 预估扫描时间
	spended := guessSmartTime(target, config)
	logs.Log.Importantf("Spraying %s with %s, Estimated to take %d seconds", target, config.Mod, spended)
	var wg sync.WaitGroup

	// 创建目标生成器
	targetGen := NewTargetGenerator(config)
	// 存活IP映射表，用于记录哪些子网是活跃的
	temp := targetGen.ipGenerator.alivedMap

	// 输出启发式扫描探针配置信息
	probeconfig := fmt.Sprintf("Smart port probes: %s ", strings.Join(config.PortProbeList, ","))
	if config.IsBSmart() {
		probeconfig += ", Smart IP probes: " + fmt.Sprintf("%v", config.IpProbeList)
	}
	logs.Log.Important(probeconfig)

	// 生成智能扫描目标通道
	// 根据扫描模式和探针生成最佳的扫描序列
	tcChannel := targetGen.smartGenerator(target, config.PortProbeList, config.Mod)

	// 创建扫描工作池
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		// 创建扫描结果对象
		result := NewResult(tc.ip, tc.port)
		// 标记为启发式探针，这会影响Dispatch中的处理逻辑
		result.SmartProbe = true
		engine.Dispatch(result)

		if result.Open {
			logs.Log.Debug("cidr scan , " + result.String())
			// 记录存活的网段 - 关键算法
			// 将单个IP的存活状态映射到整个子网
			cidrAlived(result.Ip, temp, mask)
		} else if result.Error != "" {
			logs.Log.Debugf("%s stat: %s, errmsg: %s", result.GetTarget(), PortStat[result.ErrStat], result.Error)
		}
		wg.Done()
	})
	defer scanPool.Release()

	// 提交扫描任务到工作池
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	// 等待所有扫描任务完成
	wg.Wait()

	// 处理扫描结果，收集存活网段
	var iplist utils.CIDRs
	// 遍历存活映射表，构建CIDR列表
	temp.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, utils.NewCIDR(ip.(string), mask))
		return true
	})

	// 对网段进行排序，便于输出和后续处理
	if len(iplist) > 0 {
		sort.Sort(iplist)
	} else {
		return
	}

	// 输出扫描结果
	logs.Log.Importantf("Smart scan: %s finished, found %d alive cidrs", target, len(iplist))
	// 保存B段智能扫描结果
	if config.IsBSmart() {
		WriteSmartResult(config.SmartBFile, target.String(), iplist.Strings())
	}
	// 保存C段智能扫描结果
	if config.IsCSmart() {
		WriteSmartResult(config.SmartCFile, target.String(), iplist.Strings())
	}

	// 决定是否继续深入扫描
	if Opt.NoScan || config.Mod == SUPERSMARTC {
		// -no 被设置或是C段超级模式时停止后续扫描
		return
	}
	// 创建递减扫描任务，根据智能扫描结果进行更精细的扫描
	createDeclineScan(iplist, config)
}

// AliveMod 存活检测模式：使用ICMP或ARP等协议快速检测主机存活状态
// 适用于需要快速识别存活主机的场景
// 这个模式是扫描前的预检阶段，用于减少对离线主机的无效扫描
func AliveMod(targets interface{}, config Config) {
	if !Win && !Root {
		// Linux系统下普通用户无权限使用ICMP或ARP扫描
		// 因为需要原始套接字权限，必须是root用户
		logs.Log.Warn("must be *unix's root, skipped ping/arp spray")
		DefaultMod(targets, config)
		return
	}

	var wgs sync.WaitGroup
	// 预估扫描时间
	logs.Log.Importantf("Alived spray task is expected to take %d seconds",
		guessTime(targets, len(config.AliveSprayMod), config.Threads))

	// 创建目标生成器
	targetGen := NewTargetGenerator(config)
	// 存活IP映射表
	alivedmap := targetGen.ipGenerator.alivedMap
	// 生成扫描目标通道
	targetCh := targetGen.generatorDispatch(targets, config.AliveSprayMod)

	// 创建扫描工作池
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		// 执行存活扫描
		aliveScan(i.(targetConfig), alivedmap)
		wgs.Done()
	})
	defer scanPool.Release()

	// 提交扫描任务到工作池
	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	// 等待所有扫描任务完成
	wgs.Wait()

	// 收集存活IP地址列表
	var iplist []string
	alivedmap.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, ip.(string))
		return true
	})

	// 如果没有发现存活IP，输出提示并退出
	if len(iplist) == 0 {
		logs.Log.Important("not found any alived ip")
		return
	}
	// 输出发现的存活IP数量
	logs.Log.Importantf("found %d alived ips", len(iplist))
	// 如果配置了存活结果文件，保存结果
	if config.AliveFile != nil {
		WriteSmartResult(config.AliveFile, "alive", iplist)
	}

	// 对存活IP进行深入扫描 - 这是存活模式的主要目的
	// 将存活IP列表作为DefaultMod的输入，进行端口扫描
	DefaultMod(utils.ParseIPs(iplist).CIDRs(), config)
}

// aliveScan 存活扫描辅助函数
// 检测单个目标是否存活，并记录结果
func aliveScan(tc targetConfig, temp *sync.Map) {
	// 创建扫描结果对象
	result := NewResult(tc.ip, tc.port)
	// 标记为启发式探针
	result.SmartProbe = true
	// 分发到具体的扫描模块处理
	engine.Dispatch(result)

	if result.Open {
		logs.Log.Debug("alive scan, " + result.String())
		// 存储存活状态
		temp.Store(result.Ip, true)
		// 增加存活计数
		atomic.AddInt32(&Opt.AliveSum, 1)
	}
}

// cidrAlived 网段存活记录函数：使用位掩码将IP地址归类到相应网段
// 此算法是智能扫描模式的核心，通过一个IP确认整个网段存活状态
// 参数: ip - IP地址，temp - 存活映射表，mask - 子网掩码位数
func cidrAlived(ip string, temp *sync.Map, mask int) {
	// 解析IP地址
	i := net.ParseIP(ip)
	// 应用CIDR掩码，得到网段地址
	// 例如：192.168.1.5 + 掩码24 = 192.168.1.0
	alivecidr := i.Mask(net.CIDRMask(mask, 32)).String()
	// 检查网段是否已经被标记为存活
	_, ok := temp.Load(alivecidr)
	if !ok {
		// 记录存活的网段
		temp.Store(alivecidr, 1)
		// 输出发现的网段
		logs.Log.Importantf("Found %s/%d", ip, mask)
		// 增加存活计数
		atomic.AddInt32(&Opt.AliveSum, 1)
	}
}

// createDefaultScan 创建默认扫描任务
// 根据配置选择合适的扫描模式
func createDefaultScan(config Config) {
	if config.Results != nil {
		// 如果有预先加载的结果，直接对这些结果进行扫描
		DefaultMod(config.Results, config)
	} else {
		if config.HasAlivedScan() {
			// 如果启用了存活扫描，先进行存活检测
			AliveMod(config.CIDRs, config)
		} else {
			// 否则直接使用默认模式扫描
			DefaultMod(config.CIDRs, config)
		}
	}
}

// createDeclineScan 创建递减扫描任务：从高级模式降级到基础模式
// 实现智能扫描的逐步下降策略
// 这是一个优化策略，先使用高效率低精度的方式，再逐步提高精度
func createDeclineScan(cidrs utils.CIDRs, config Config) {
	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == SUPERSMART {
		// 如果port数量为1, 直接扫描的耗时小于启发式
		// 如果port数量为2, 直接扫描的耗时约等于启发式扫描
		// 因此, 如果post数量小于等于2, 则直接使用defaultScan
		config.Mod = SMART
		if len(config.PortList) <= 3 {
			logs.Log.Important("ports less than 3, skipped smart scan.")
			if config.HasAlivedScan() {
				// 使用存活检测模式
				AliveMod(config.CIDRs, config)
			} else {
				// 使用默认扫描模式
				DefaultMod(config.CIDRs, config)
			}
		} else {
			// 超过3个端口，继续使用智能扫描
			spended := guessSmartTime(cidrs[0], config)
			logs.Log.Importantf("Every smartscan subtask is expected to take %d seconds, total found %d B Class CIDRs about %d s", spended, len(cidrs), spended*len(cidrs))
			// 逐个处理B类网段
			for _, ip := range cidrs {
				tmpalive := Opt.AliveSum
				// 对每个B类网段进行智能扫描
				SmartMod(ip, config)
				logs.Log.Importantf("Found %d assets from CIDR %s", Opt.AliveSum-tmpalive, ip)
				// 同步文件，确保结果及时写入
				syncFile()
			}
		}
	} else if config.Mod == SUPERSMARTB {
		// 喷洒B段 - 对每个B类网段进行C类智能扫描
		for _, ip := range cidrs {
			config.Mod = SUPERSMARTC
			tmpalive := Opt.AliveSum
			// 使用C段超级模式扫描
			SmartMod(ip, config)
			logs.Log.Importantf("Found %d assets from CIDR %s", Opt.AliveSum-tmpalive, ip)
			// 同步文件，确保结果及时写入
			syncFile()
		}
	} else if config.Mod == SMART {
		if config.HasAlivedScan() {
			// 使用存活模式扫描C段网段
			AliveMod(cidrs, config)
		} else {
			// 使用默认模式扫描C段网段
			DefaultMod(cidrs, config)
		}
	}
}
