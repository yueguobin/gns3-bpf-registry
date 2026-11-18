/* prototype/i18n.js — UI-chrome strings and the lookup helpers.
   English is the default language; Chinese is optional and complete.

   Two string populations exist and they must not mix:
   - UI CHROME (this file): every fixed label, tooltip and note the page
     itself renders. STR.en and STR.zh declare identical key sets;
     tools/check_i18n.py verifies that plus "no CJK in index.html".
   - DATA (registry/*.json and prototype/overlay.js): per-entry notes,
     exclusion reasons and family labels travel WITH the entry as inline
     {en, zh} objects resolved through L(); they are content, not chrome,
     and never move into this file.

   The GNS3 web UI ports this file into its own i18n catalogs (vue-i18n
   or equivalent); see docs/ui-contract.md section 7. */

let LANG = "en";
try{ LANG = localStorage.getItem("bpfcalc-lang") || "en"; }catch(e){}

const STR = {
  en:{
    title:"BPF Expression Visual Calculator",
    sub:"Stack protocol bricks like building a packet — every field visible in its textbook word grid, click a field to input a value, offsets are computed for you. Never count bytes again.",
    sec1:"1 · Packet Construction", sec2:"2 · Selected Conditions & Guards", sec3:"3 · Generated BPF Expression",
    pal:"Bricks", searchPh:"Search protocols…",
    customBtn:"+ Custom layer (declare length)", customPrompt:"Custom layer length (bytes)",
    noFields:"Custom layer has no fields; its job is to advance the offset ruler.",
    offset:"offset", drillL:" · drill", tunnelL:" · tunnel",
    inner:"📦 Inner packet · ${label} payload (drill: absolute offsets + guards)",
    innerEmpty:"No inner packet yet — bricks added next become the tunnel payload",
    emptyStack:"Add bricks from the rail…",
    total:n=>`Total ${n} bytes`,
    noneYet:"No field selected yet",
    modeNative:"Native (keyword anchors)", modeDrill:"Drill (absolute offsets + guards)",
    noteDrill:"Drill mode: absolute offsets come from the accumulated ruler; guard clauses verify the declared encapsulation — mismatches safe-miss, never false-match.",
    noteNative:"Native mode: keyword anchors / primitives; libpcap handles outer IHL/VLAN.",
    guard:"Guard", ihlPin:"IHL pin", optPin:"optional-field pin",
    warnMis:(a,b,c)=>`${a}=${b} points to ${c}`,
    warnTail:", but the next layer is ",
    clickDd:"; click for dropdown", dblIn:"; double-click to input", letTgl:"; click letters to toggle",
    notFilterable:"not filterable", exclConst:"constant, not filterable",
    prim1:"native emits \"", prim2:"\", drill emits the byte window",
    value:"value", langOther:"中文", tailVar:l=>`${l} (variable)`,
    tipMeta:(l,o,w,k)=>`${l} · offset ${o}B · ${w}bit · ${k}`,
    primBadge:"primitive",
    w32:"32-bit",
    warnTitle:"Structure mismatch: with this encapsulation the condition never matches",
    hintTitle:"Structure hint",
    pinWarnGeneric:"Tunnel optional fields set: inner-packet offsets below assume the base header",
    loading:"Loading protocol registry…",
    loadingProg:(d,n)=>`Loading protocols… ${d} / ${n}`,
    loadFail:"Cannot load registry/*.json next to the page.\nServe the repository over HTTP and open the page from there:\n\n  python3 -m http.server\n  http://localhost:8000/prototype/",
  },
  zh:{
    title:"BPF 表达式可视化计算器",
    sub:"像搭报文一样逐层拼积木,每个字段按教科书 32 位字格展示;点字段输入值,偏移自动计算,用户永远不数字节。",
    sec1:"1 · 报文构造", sec2:"2 · 已选条件与守卫", sec3:"3 · 生成的 BPF 表达式",
    pal:"层积木", searchPh:"搜索协议…",
    customBtn:"＋ 自定义层(声明长度)", customPrompt:"自定义层长度(字节)",
    noFields:"自定义层无字段,作用是推进标尺。",
    offset:"累计偏移", drillL:" · 钻取层", tunnelL:" · 隧道",
    inner:"📦 内层报文 · ${label} 载荷（钻取:绝对偏移 + 守卫）",
    innerEmpty:"尚无内层报文 — 继续添加积木,它们会成为隧道载荷",
    emptyStack:"从右侧积木栏添加层…",
    total:n=>`报文总长 ${n} 字节`,
    noneYet:"尚未选择字段",
    modeNative:"原生模式(关键字锚点)", modeDrill:"钻取模式(绝对偏移+守卫)",
    noteDrill:"钻取模式:绝对偏移由累计标尺计算;守卫子句校验声明的封装,错配安全漏报、永不误匹配。",
    noteNative:"原生模式:关键字锚点/原语,libpcap 自动处理外层 IHL/VLAN。",
    guard:"守卫", ihlPin:"IHL 钉子", optPin:"可选字段钉子",
    warnMis:(a,b,c)=>`${a}.${b}=${c}`,
    warnTail:",下一层却是 ",
    clickDd:"；点击下拉选择", dblIn:"；双击直接输入", letTgl:"；点击字母位直接开关",
    notFilterable:"不可过滤", exclConst:"常量,不可过滤",
    prim1:"原生输出「", prim2:"」,钻取输出字节窗口",
    value:"数值", langOther:"English", tailVar:l=>`${l}（变长）`,
    tipMeta:(l,o,w,k)=>`${l} · 偏移 ${o}B · ${w}bit · ${k}`,
    primBadge:"原语",
    w32:"32 位",
    warnTitle:"结构不符:按此封装,该条件永不匹配",
    hintTitle:"结构提示",
    pinWarnGeneric:"隧道可选字段置位:以下内层偏移按基本头计算",
    loading:"正在加载协议注册表…",
    loadingProg:(d,n)=>`正在加载协议… ${d} / ${n}`,
    loadFail:"无法加载页面旁的 registry/*.json。\n请通过 HTTP 提供本仓库后再打开页面:\n\n  python3 -m http.server\n  http://localhost:8000/prototype/",
  },
};

function T(k){ const v = STR[LANG] && STR[LANG][k]; return v===undefined ? (STR.en[k] ?? k) : v; }
function L(x){ return x && typeof x==="object" ? (x[LANG] ?? x.en) : x; }
