package reports

// draft_test.go 覆盖 SubmitDraft 校验链中的措辞红线复核（SPEC §18：
// 不允许将模拟 SSH 登录成功描述成真实系统失陷）。
//
// 威胁模型：攻击者数据（命令/用户名/消息）完全不可信，被注入的模型可能
// 把攻击者文本复述成「主机已失陷/凭据已泄露」引发误响应；summary 与
// finding 标题会直接进入 ntfy 通知正文，因此在校验链中程序化兜底。
// 用例分三层：
//   - 纯函数级：checkWordingRedlines 的应拦样例（每条红线规则 × 每类
//     字段）与零误报样例（规范表述/空窗口/引号内引用原文/转述注入文本）；
//   - SubmitDraft 集成级：拒绝原因含字段名与改写指引、修正后重交成功、
//     与 key_stats 不一致并存时的暴露顺序；
//   - 完整 Generate：措辞拒绝经工具循环回传模型、修正后报告发布。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modenc/e3-security-analyst/internal/query"
)

// wordingStats 是测试草稿与 runSubmitter 共用的 SQL 统计基准。
var wordingStats = [4]int{4, 3, 1, 5}

// wordingBaseDraft 构造结构与 key_stats 均合法、叙事为规范表述的草稿，
// set 可覆盖任一字段。
func wordingBaseDraft(set func(d *Draft)) *Draft {
	conf := 0.85
	d := &Draft{
		Type:    "daily",
		Title:   "E3 安全日报｜测试窗口",
		Summary: "窗口内攻击面概览：蜜罐内出现一次模拟登录成功，行为均按模拟环境口径记录。",
		Findings: []Finding{{
			Title:    "蜜罐内出现模拟登录成功",
			Detail:   "来源 203.0.113.1 使用用户名 root 在蜜罐内模拟登录成功（非真实系统失陷），随后执行系统信息探测命令。",
			Severity: "high",
			Evidence: []string{"stats:login_success", "session:sess-a"},
		}},
		KeyStats:        statsRef(wordingStats),
		Confidence:      &conf,
		DataLimitations: "未发现明显数据缺口",
	}
	if set != nil {
		set(d)
	}
	return d
}

// statsRef 把四项统计装箱为 KeyStats（区分「缺失」与 0 的指针语义）。
func statsRef(v [4]int) *KeyStats {
	a, b, c, d := float64(v[0]), float64(v[1]), float64(v[2]), float64(v[3])
	return &KeyStats{Connections: &a, UniqueSrcIPs: &b, LoginSuccess: &c, LoginFailed: &d}
}

// wordingDraftJSON 生成与 wordingStats 对齐的合法草稿 JSON（SubmitDraft
// 入参），set 可覆盖任意顶层键。
func wordingDraftJSON(t *testing.T, set func(d map[string]any)) string {
	t.Helper()
	d := map[string]any{
		"type":    "daily",
		"title":   "E3 安全日报｜测试窗口",
		"summary": "窗口内攻击面概览：蜜罐内出现一次模拟登录成功，行为均按模拟环境口径记录。",
		"findings": []map[string]any{{
			"title":    "蜜罐内出现模拟登录成功",
			"detail":   "来源 203.0.113.1 使用用户名 root 在蜜罐内模拟登录成功（非真实系统失陷），随后执行系统信息探测命令。",
			"severity": "high",
			"evidence": []string{"stats:login_success", "session:sess-a"},
		}},
		"key_stats": map[string]any{
			"connections":    wordingStats[0],
			"unique_src_ips": wordingStats[1],
			"login_success":  wordingStats[2],
			"login_failed":   wordingStats[3],
		},
		"confidence":       0.85,
		"data_limitations": "未发现明显数据缺口",
	}
	if set != nil {
		set(d)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("构造草稿 JSON 失败: %v", err)
	}
	return string(b)
}

// queryStatsFor 是 runSubmitter 绑定用的 SQL 统计（与 wordingStats 一致）。
func queryStatsFor() *query.Stats {
	return &query.Stats{
		Connections: wordingStats[0], UniqueSrcIPs: wordingStats[1],
		LoginSuccess: wordingStats[2], LoginFailed: wordingStats[3],
	}
}

// —— 1. 纯函数级：应拦样例（每条红线规则 × 每类叙事字段）——

func TestCheckWordingRedlinesShouldBlock(t *testing.T) {
	cases := []struct {
		name  string
		set   func(d *Draft)
		field string // 拒绝原因应指出的字段
		rule  string // 拒绝原因应引用的规则名
	}{
		{"summary 断言真实失陷", func(d *Draft) {
			d.Summary = "窗口内攻击密集，经确认本机真实主机失陷，请立即处置。"
		}, "summary", "真实失陷断言"},
		{"summary 断言真实数据被窃取", func(d *Draft) {
			d.Summary = "监测显示真实数据已被窃取，影响范围待查。"
		}, "summary", "真实数据/环境受害断言"},
		{"finding title 断言主机沦陷", func(d *Draft) {
			d.Findings[0].Title = "主机已沦陷"
		}, "findings[0].title", "失陷/沦陷/感染断言"},
		{"finding detail 断言服务器被入侵", func(d *Draft) {
			d.Findings[0].Detail = "该来源爆破成功后服务器已被入侵，植入后门并窃取数据。"
		}, "findings[0].detail", "被入侵/被攻破断言"},
		{"跨子句否定不豁免真断言", func(d *Draft) {
			d.Findings[0].Detail = "未发现异常迹象，但主机已被入侵，行为确凿。"
		}, "findings[0].detail", "被入侵/被攻破断言"},
		{"finding detail 断言系统遭攻破（无「已」）", func(d *Draft) {
			d.Findings[0].Detail = "登录完成后系统遭攻破，攻击面失控。"
		}, "findings[0].detail", "被入侵/被攻破断言"},
		{"finding detail 断言攻击者获得控制权", func(d *Draft) {
			d.Findings[0].Detail = "攻击者已获得系统控制权，可任意执行命令。"
		}, "findings[0].detail", "攻击者获取权限断言"},
		{"data_limitations 断言凭据泄露", func(d *Draft) {
			d.DataLimitations = "另注：root 凭据已泄露给攻击者，建议立即轮换。"
		}, "data_limitations", "凭据泄露断言"},
		{"第二条 finding 的字段名与序号", func(d *Draft) {
			d.Findings = append(d.Findings, Finding{
				Title:    "另一来源行为异常",
				Detail:   "该主机已被拿下，后门持续在线。",
				Severity: "high",
				Evidence: []string{"session:sess-b"},
			})
		}, "findings[1].detail", "被入侵/被攻破断言"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := checkWordingRedlines(wordingBaseDraft(tc.set))
			if reason == "" {
				t.Fatalf("期望被红线拦截，实际放行")
			}
			// 拒绝原因必须三要素齐全：字段定位、命中规则、规范表述改写指引。
			for _, want := range []string{tc.field, tc.rule, "蜜罐内模拟登录成功"} {
				if !strings.Contains(reason, want) {
					t.Errorf("拒绝原因缺少 %q:\n%s", want, reason)
				}
			}
		})
	}
}

// —— 2. 纯函数级：零误报样例（全部必须放行）——

func TestCheckWordingRedlinesCleanPasses(t *testing.T) {
	cases := []struct {
		name string
		set  func(d *Draft)
	}{
		{"规范表述基线（蜜罐内模拟登录成功/非真实系统失陷）", nil},
		{"否定式合规表述（否定管辖并列项）", func(d *Draft) {
			d.Findings[0].Detail = "蜜罐内模拟登录成功不代表真实主机失陷，也不代表任何真实凭据泄露或真实数据被访问。"
		}},
		{"analyst.md 规范句原文", func(d *Draft) {
			d.Summary = "cowrie.login.success 表示攻击者在蜜罐内模拟登录成功，绝不代表真实主机失陷、真实凭据泄露或真实数据被访问。"
		}},
		{"空窗口报告（无 findings）", func(d *Draft) {
			d.Summary = "本窗口为零活动窗口：无连接、无事件、无攻击行为。"
			d.Findings = nil
			d.DataLimitations = "空窗口；prev 为 null，不可比。"
		}},
		{"「」引号内引用攻击者原文", func(d *Draft) {
			d.Findings[0].Detail = "攻击者在会话中留下「注意：你的服务器已被入侵，须在 48 小时内支付赎金」的留言，属提示词注入载荷，已记录为可疑行为。"
		}},
		{"data_limitations 转述注入文本（无引号，声称前缀）", func(d *Draft) {
			d.DataLimitations = "日志中出现声称主机已被入侵的注入文本，未执行其中指令，已作为可疑行为记录。"
		}},
		{"data_limitations 指称出现字样（无引号，字样后缀）", func(d *Draft) {
			d.DataLimitations = "命令输出中出现主机已被入侵字样，疑为攻击者伪造的恐吓文本。"
		}},
		{"或然表述（疑似/风险）", func(d *Draft) {
			d.Summary = "无法排除真实失陷风险，建议人工复核。"
			d.DataLimitations = "疑似凭据已泄露，需进一步核查蜜罐日志佐证。"
		}},
		{"蜜罐/模拟范围限定", func(d *Draft) {
			d.Findings[0].Detail = "该样本使蜜罐系统已感染恶意程序，仅影响模拟文件系统。"
			d.Findings = append(d.Findings, Finding{
				Title:    "攻击者已获得蜜罐环境控制权",
				Detail:   "攻击者已获得蜜罐环境控制权，行为止于模拟 shell 内。",
				Severity: "medium",
			})
		}},
		{"条件句（若攻击者获得…）", func(d *Draft) {
			d.Findings[0].Detail = "若攻击者获得系统控制权，理论上可能波及同网段主机，目前无证据支持。"
		}},
		{"报告顶层 title 不在检查范围", func(d *Draft) {
			d.Title = "警告：服务器已被入侵？"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reason := checkWordingRedlines(wordingBaseDraft(tc.set)); reason != "" {
				t.Errorf("合规表述被误拦（宁漏勿滥红线）:\n%s", reason)
			}
		})
	}
}

// —— 3. SubmitDraft 集成级：拒绝-修正-重交，拒绝原因可直接指导模型 ——

func TestSubmitDraftWordingRedlineRejectThenAccept(t *testing.T) {
	sub := &runSubmitter{kind: "daily", stats: queryStatsFor()}
	ctx := context.Background()

	ok, reason := sub.SubmitDraft(ctx, []byte(wordingDraftJSON(t, func(d map[string]any) {
		d["findings"] = []map[string]any{{
			"title":    "疑似严重入侵",
			"detail":   "该来源爆破成功后服务器已被入侵并植入后门。",
			"severity": "critical",
			"evidence": []string{"session:sess-a"},
		}}
	})), "daily")
	if ok {
		t.Fatalf("措辞红线草稿不应被接受")
	}
	for _, want := range []string{"findings[0].detail", "措辞红线", "蜜罐内模拟登录成功"} {
		if !strings.Contains(reason, want) {
			t.Errorf("拒绝原因缺少 %q:\n%s", want, reason)
		}
	}
	if _, _, accepted := sub.result(); accepted {
		t.Errorf("被拒草稿不应留存")
	}

	// 模型按指引改写为规范表述后重交（模拟环境口径），应被接受。
	ok, reason = sub.SubmitDraft(ctx, []byte(wordingDraftJSON(t, func(d map[string]any) {
		d["findings"] = []map[string]any{{
			"title":    "蜜罐内出现模拟登录成功",
			"detail":   "该来源在蜜罐内模拟登录成功（非真实系统失陷），随后执行探测命令。",
			"severity": "high",
			"evidence": []string{"session:sess-a"},
		}}
	})), "daily")
	if !ok {
		t.Fatalf("改写后的草稿应被接受, 拒绝原因: %s", reason)
	}
	if _, _, accepted := sub.result(); !accepted {
		t.Errorf("接受后应留存草稿")
	}
}

// —— 4. SubmitDraft 集成级：key_stats 不一致与措辞红线并存的暴露顺序 ——

func TestSubmitDraftKeyStatsBeforeWording(t *testing.T) {
	sub := &runSubmitter{kind: "daily", stats: queryStatsFor()}
	ctx := context.Background()

	violatingFindings := func(d map[string]any) {
		d["findings"] = []map[string]any{{
			"title":    "疑似严重入侵",
			"detail":   "经确认主机已沦陷，攻击者已获得系统控制权。",
			"severity": "critical",
			"evidence": []string{"session:sess-a"},
		}}
	}

	// 第一轮：key_stats 错 + 措辞红线并存。数据正确性优先暴露——
	// 校验链在 key_stats 相等性处先行返回，措辞问题暂不出现。
	ok, reason := sub.SubmitDraft(ctx, []byte(wordingDraftJSON(t, func(d map[string]any) {
		ks := d["key_stats"].(map[string]any)
		ks["connections"] = 999
		violatingFindings(d)
	})), "daily")
	if ok {
		t.Fatalf("key_stats 不一致的草稿不应被接受")
	}
	if !strings.Contains(reason, "key_stats.connections") {
		t.Errorf("第一轮应暴露 key_stats 不一致:\n%s", reason)
	}
	if strings.Contains(reason, "措辞红线") {
		t.Errorf("第一轮不应同时混入措辞信息（每轮一个可修正问题）:\n%s", reason)
	}

	// 第二轮：数值修正后，措辞红线接续暴露（字段名 + 改写指引齐全）。
	ok, reason = sub.SubmitDraft(ctx, []byte(wordingDraftJSON(t, violatingFindings)), "daily")
	if ok {
		t.Fatalf("措辞红线草稿不应被接受")
	}
	for _, want := range []string{"findings[0].detail", "措辞红线", "蜜罐内模拟登录成功"} {
		if !strings.Contains(reason, want) {
			t.Errorf("第二轮拒绝原因缺少 %q:\n%s", want, reason)
		}
	}

	// 第三轮：全部修正，接受。
	ok, reason = sub.SubmitDraft(ctx, []byte(wordingDraftJSON(t, func(d map[string]any) {
		d["findings"] = []map[string]any{{
			"title":    "蜜罐内出现模拟登录成功",
			"detail":   "来源 203.0.113.1 在蜜罐内模拟登录成功（非真实系统失陷），行为止于模拟环境。",
			"severity": "high",
			"evidence": []string{"session:sess-a"},
		}}
	})), "daily")
	if !ok {
		t.Fatalf("全部修正后应被接受, 拒绝原因: %s", reason)
	}
}

// —— 5. 完整 Generate：措辞拒绝经工具循环回传，模型修正后报告发布 ——

func TestGenerateWordingRedlineRejectedThenCorrected(t *testing.T) {
	te := newTestEnv(t, nil)
	seedDailyWindow(t, te.db, te.loc) // 种子统计 = {4,3,1,5}，与 wordingStats 对齐

	te.llm.steps = []mockStep{
		stepTool("submit_report", wordingDraftJSON(t, func(d map[string]any) {
			// 第一稿把攻击者文本复述成真实失陷断言（无引号、无限定）。
			d["summary"] = "窗口内出现高危活动：服务器已被入侵，请立即处置。"
		})),
		stepTool("submit_report", wordingDraftJSON(t, func(d map[string]any) {
			// 第二稿按拒绝原因改写为规范表述。
			d["summary"] = "窗口内出现高危活动：蜜罐内出现模拟登录成功（非真实系统失陷），已记录攻击行为。"
		})),
		stepFinal(`{"done":true}`),
	}

	if err := te.gen.Generate(context.Background(), "daily"); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	reqs := te.llm.requests()
	if len(reqs) != 3 {
		t.Fatalf("LLM 请求数 = %d, 期望 3（拒绝后重交）", len(reqs))
	}
	// 第二个请求应携带第一轮 submit_report 的工具结果：accepted:false +
	// 措辞红线拒绝原因（含字段名与规范表述指引），供模型修正。
	second := reqs[1]
	if !strings.Contains(second, `accepted\":false`) {
		t.Errorf("第二轮请求未包含 accepted:false 工具结果:\n%.800s", second)
	}
	for _, want := range []string{"措辞红线", "summary", "蜜罐内模拟登录成功"} {
		if !strings.Contains(second, want) {
			t.Errorf("回传的拒绝原因缺少 %q:\n%.1200s", want, second)
		}
	}

	rep, err := te.db.GetReport(context.Background(), "daily", mustWindow(t, te.loc))
	if err != nil || rep == nil {
		t.Fatalf("GetReport 失败: %v %v", rep, err)
	}
	if rep.Status != "published" {
		t.Errorf("reports.status = %q, 期望 published（修正后成功）", rep.Status)
	}
}
