package main

import (
	"MySecurityProject/dis_character"
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// --- 基础结构体定义 ---

type AdjacentChar struct {
	Char  rune
	Value float64
}

type ConfusableChar struct {
	Char       rune
	Similarity float64
}

type ReplaceStats struct {
	From, To rune
	Count    int
}

type Scored struct {
	domain   string
	punycode string
	sim      float64
	isUni    bool
}

// --- 全局变量配置 ---

var keyboardAdjacentsWithProb = map[rune][]AdjacentChar{
	'a': {{'d', 0.042263358219502}, {'e', 0.042263358219502}, {'q', 0.078489093836218}, {'s', 0.0824135485280289}, {'w', 0.0686779571066907}, {'x', 0.0470934563017308}, {'z', 0.0749214077527535}, {'1', 0.0402017309892824}, {'2', 0.042263358219502}},
	'b': {{'g', 0.063500444738821}, {'h', 0.063500444738821}, {'n', 0.0698504892127031}, {'v', 0.0698504892127031}},
	'c': {{'d', 0.0643192976962591}, {'f', 0.067382121396081}, {'v', 0.0707512274658851}, {'x', 0.0707512274658851}},
	'd': {{'c', 0.057843470587944}, {'e', 0.0636278176467385}, {'f', 0.0636278176467385}, {'r', 0.053023181372282}, {'s', 0.0636278176467385}, {'x', 0.0553285370841204}},
	'e': {{'d', 0.0639591129670347}, {'f', 0.0412639438496998}, {'r', 0.0639591129670347}, {'s', 0.0532992608058622}, {'w', 0.0639591129670347}, {'3', 0.0581446481518497}, {'4', 0.0581446481518497}},
	'f': {{'c', 0.0583499653547185}, {'d', 0.0612674636224544}, {'e', 0.0395273958854544}, {'g', 0.0612674636224544}, {'r', 0.0583499653547185}, {'t', 0.0510562196853787}, {'v', 0.0532760553238734}},
	'g': {{'b', 0.055231250012246}, {'f', 0.0607543750134706}, {'h', 0.0607543750134706}, {'r', 0.0391963709764326}, {'t', 0.0607543750134706}, {'v', 0.055231250012246}, {'y', 0.0506286458445588}},
	'h': {{'b', 0.0564575043095919}, {'g', 0.0621032547405511}, {'j', 0.0621032547405511}, {'n', 0.0564575043095919}, {'u', 0.0496826037924408}, {'y', 0.0591459568957629}},
	'i': {{'j', 0.0560735767711215}, {'k', 0.0640840877384246}, {'l', 0.0420551825783411}, {'o', 0.0672882921253458}, {'u', 0.0672882921253458}, {'8', 0.0640840877384246}, {'9', 0.0640840877384246}},
	'j': {{'h', 0.0647427573313783}, {'i', 0.0539522977761486}, {'k', 0.0647427573313783}, {'m', 0.061659768887027}, {'n', 0.061659768887027}, {'u', 0.061659768887027}},
	'k': {{'i', 0.0686627721374045}, {'j', 0.0720959107442747}, {'l', 0.0720959107442747}, {'m', 0.0686627721374045}, {'n', 0.0424093592613381}, {'o', 0.0600799256202289}, {'u', 0.0450599442151717}},
	'l': {{'i', 0.0547405897159169}, {'j', 0.0449153556643421}, {'k', 0.0875849435454671}, {'m', 0.0500485391688383}, {'o', 0.0834142319480639}, {'p', 0.0700679548363737}, {'0', 0.0460973387081406}, {'9', 0.0427243627051059}},
	'm': {{'j', 0.0756762029534081}, {'k', 0.0756762029534081}, {'n', 0.0794600131010785}},
	'n': {{'b', 0.0722761749636009}, {'h', 0.0657056136032735}, {'j', 0.0688344523462865}, {'m', 0.0722761749636009}},
	'o': {{'i', 0.0758350662718647}, {'k', 0.0631958885598872}, {'l', 0.0722238726398711}, {'p', 0.0758350662718647}, {'0', 0.0722238726398711}, {'8', 0.0446088625128616}, {'9', 0.0722238726398711}},
	'p': {{'i', 0.0500919128222846}, {'k', 0.0500919128222846}, {'l', 0.0781433840027649}, {'o', 0.097679230003455}, {'0', 0.0930278380985285}, {'9', 0.0558167028591171}},
	'q': {{'a', 0.0801569721449232}, {'s', 0.0526030129701058}, {'w', 0.0841648207521693}, {'1', 0.076513473411063}, {'2', 0.076513473411063}, {'3', 0.0480941832869539}},
	'r': {{'d', 0.0511267521411718}, {'e', 0.0613521025694062}, {'f', 0.058430573875625}, {'g', 0.0395820016576814}, {'t', 0.0613521025694062}, {'4', 0.0570717233203779}, {'5', 0.0557746386994602}},
	's': {{'a', 0.0684130784134019}, {'d', 0.0684130784134019}, {'e', 0.0570108986778349}, {'q', 0.0427581740083762}, {'w', 0.0651553127746685}, {'x', 0.0651553127746685}, {'z', 0.0651553127746685}},
	't': {{'f', 0.0501603490071326}, {'g', 0.0601924188085592}, {'r', 0.0601924188085592}, {'y', 0.0601924188085592}, {'5', 0.0573261131510088}, {'6', 0.0547203807350538}},
	'u': {{'h', 0.0505430569371885}, {'i', 0.0631788211714856}, {'j', 0.0601703058776053}, {'y', 0.0631788211714856}, {'7', 0.0601703058776053}, {'8', 0.0587709964385912}},
	'v': {{'b', 0.0698033790922847}, {'c', 0.0698033790922847}, {'f', 0.0606985905150302}, {'g', 0.0634576173566225}},
	'w': {{'a', 0.0580055187340927}, {'d', 0.0435041390505695}, {'e', 0.0696066224809112}, {'q', 0.0696066224809112}, {'s', 0.0662920214103916}, {'1', 0.0409450720475948}, {'2', 0.0662920214103916}, {'3', 0.0632787477099193}, {'4', 0.0397752128462349}},
	'x': {{'c', 0.075290652947669}, {'d', 0.065470132997973}, {'s', 0.0717053837596847}, {'z', 0.075290652947669}},
	'y': {{'g', 0.0506734011547479}, {'h', 0.0579124584625691}, {'t', 0.0608080813856975}, {'u', 0.0608080813856975}, {'6', 0.0579124584625691}, {'7', 0.0565656571029744}},
	'z': {{'a', 0.0779400647539303}, {'s', 0.0816514964088793}, {'x', 0.0857340712293233}},
}

var dictWords = []string{"login", "secure", "update", "auth", "verify", "account", "user", "my"}
var illegalFilenameChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)

var (
	replaceStatsMu sync.Mutex
)

// 可配置的全局运行参数（如果未通过命令行设置，使用下面的默认值）
var MaxVariants int64 = 1 << 62 // 生成变体的全局上限，防止无限制分配
var WorkersLimit int = 0        // 若为 0 则使用 GOMAXPROCS，否则强制设置 worker 数量

// --- 核心算法函数 (保留原有逻辑) ---

func sanitizeFilename(name string) string {
	name = illegalFilenameChars.ReplaceAllString(name, "_")
	if name == "" {
		name = "domain"
	}
	return name
}

func combinations(n, m int) [][]int {
	var result [][]int
	var backtrack func(start int, current []int)
	backtrack = func(start int, current []int) {
		if len(current) == m {
			temp := make([]int, m)
			copy(temp, current)
			result = append(result, temp)
			return
		}
		for i := start; i < n; i++ {
			current = append(current, i)
			backtrack(i+1, current)
			current = current[:len(current)-1]
		}
	}
	backtrack(0, []int{})
	return result
}

func insertCombinations(n, m int) [][]int {
	var result [][]int
	var backtrack func(start int, current []int)
	backtrack = func(start int, current []int) {
		if len(current) == m {
			temp := make([]int, m)
			copy(temp, current)
			result = append(result, temp)
			return
		}
		for i := start; i <= n; i++ {
			current = append(current, i)
			backtrack(i+1, current)
			current = current[:len(current)-1]
		}
	}
	backtrack(0, []int{})
	return result
}

func getMaxReplacements(sldLen int) int {
	switch {
	case sldLen <= 3:
		return 1
	case sldLen <= 6:
		return 2
	default:
		return 3
	}
}

func toPunycode(domain string) string {
	p, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return p
}

func extractDomainParts(domain string) (subdomain string, sld string, tld string) {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		if idx := strings.LastIndex(domain, "."); idx != -1 {
			return "", domain[:idx], domain[idx+1:]
		}
		return "", domain, ""
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	tld = suffix
	if len(eTLDPlusOne) > len(suffix)+1 {
		sld = eTLDPlusOne[:len(eTLDPlusOne)-len(suffix)-1]
	} else {
		sld = eTLDPlusOne
	}
	if len(domain) > len(eTLDPlusOne)+1 {
		subdomain = domain[:len(domain)-len(eTLDPlusOne)-1]
	}
	return subdomain, sld, tld
}

func weightedSample(chars []dis_character.ConfusableChar) rune {
	if len(chars) == 0 {
		return 0
	}
	total := 0.0
	for _, c := range chars {
		total += c.Similarity
	}
	r := rand.Float64() * total
	for _, c := range chars {
		r -= c.Similarity
		if r <= 0 {
			return c.Char
		}
	}
	return chars[len(chars)-1].Char
}

func visualSimilarity(orig, variant string) float64 {
	o := []rune(strings.ToLower(orig))
	v := []rune(strings.ToLower(variant))
	n := len(o)
	if n == 0 {
		return 0.0
	}
	score := 0.0
	i, j := 0, 0
	for i < n && j < len(v) {
		if o[i] == v[j] {
			score += 1.0
			i++
			j++
			continue
		}
		if list, ok := dis_character.ConfusablesMap[o[i]]; ok {
			for _, c := range list {
				if c.Char == v[j] {
					score += c.Similarity
					i++
					j++
					goto next
				}
			}
		}
		j++
	next:
	}
	penalty := math.Min(1.0, float64(n)/float64(len(v)+1))
	return (score/float64(n))*0.88 + penalty*0.12
}

// --- 生成器函数 ---

func replaceWithConfusables(s string, m int) []string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 || m <= 0 || m > n {
		return nil
	}
	positions := combinations(n, m)
	var results []string
	for _, pos := range positions {
		var choices [][]rune
		validCombo := true
		for _, idx := range pos {
			orig := runes[idx]
			lower := unicode.ToLower(orig)
			var candidates []rune
			if list, exists := dis_character.ConfusablesMap[lower]; exists {
				for _, c := range list {
					if c.Char == lower {
						continue
					}
					var targetChar rune
					if unicode.IsUpper(orig) {
						targetChar = unicode.ToUpper(c.Char)
					} else {
						targetChar = c.Char
					}
					candidates = append(candidates, targetChar)
				}
			}
			if len(candidates) == 0 {
				validCombo = false
				break
			}
			choices = append(choices, candidates)
		}
		if !validCombo {
			continue
		}
		var generate func(depth int, current []rune)
		generate = func(depth int, current []rune) {
			if depth == len(choices) {
				cpy := make([]rune, n)
				copy(cpy, runes)
				for i, idx := range pos {
					cpy[idx] = current[i]
				}
				results = append(results, string(cpy))
				return
			}
			for _, ch := range choices[depth] {
				generate(depth+1, append(current, ch))
			}
		}
		generate(0, make([]rune, 0, len(pos)))
	}
	return results
}

// 流式生成 replaceWithConfusables 的变体，不一次性分配所有结果。
// ctx: 可取消的上下文；out: 输出通道（接收每个变体）；total/maxTotal: 可选的全局计数控制（传入很大值表示不限制）。
func replaceWithConfusablesStream(ctx context.Context, s string, m int, out chan<- string, total *int64, maxTotal int64) {
	runes := []rune(s)
	n := len(runes)
	if n == 0 || m <= 0 || m > n {
		return
	}

	var choose func(start int, cur []int)
	choose = func(start int, cur []int) {
		// 取消检查
		select {
		case <-ctx.Done():
			return
		default:
		}
		if len(cur) == m {
			// 为当前位置组合构建候选列表
			choices := make([][]rune, 0, m)
			for _, idx := range cur {
				orig := runes[idx]
				lower := unicode.ToLower(orig)
				var candidates []rune
				if list, exists := dis_character.ConfusablesMap[lower]; exists {
					for _, c := range list {
						if c.Char == lower {
							continue
						}
						if unicode.IsUpper(orig) {
							candidates = append(candidates, unicode.ToUpper(c.Char))
						} else {
							candidates = append(candidates, c.Char)
						}
					}
				}
				if len(candidates) == 0 {
					return // 此位置组合无效，跳过
				}
				choices = append(choices, candidates)
			}

			// 递归生成笛卡尔积并发送
			var gen func(depth int, current []rune)
			gen = func(depth int, current []rune) {
				// 取消检查
				select {
				case <-ctx.Done():
					return
				default:
				}
				if depth == len(choices) {
					// 组装最终变体
					cpy := make([]rune, n)
					copy(cpy, runes)
					for i, idx := range cur {
						cpy[idx] = current[i]
					}
					// 检查全局计数
					if total != nil {
						if atomic.LoadInt64(total) >= maxTotal {
							return
						}
						if atomic.AddInt64(total, 1) > maxTotal {
							return
						}
					}
					select {
					case <-ctx.Done():
						return
					case out <- string(cpy):
					}
					return
				}
				for _, ch := range choices[depth] {
					gen(depth+1, append(current, ch))
					// 如果上下文取消或达到上限，尽早返回
					select {
					case <-ctx.Done():
						return
					default:
					}
					if total != nil && atomic.LoadInt64(total) >= maxTotal {
						return
					}
				}
			}
			gen(0, make([]rune, 0, len(choices)))
			return
		}
		for i := start; i <= n-(m-len(cur)); i++ {
			choose(i+1, append(cur, i))
			// 检查取消
			select {
			case <-ctx.Done():
				return
			default:
			}
			if total != nil && atomic.LoadInt64(total) >= maxTotal {
				return
			}
		}
	}

	choose(0, []int{})
}

// insertConfusablesStream: 流式生成 insertConfusables 的变体
func insertConfusablesStream(ctx context.Context, s string, m int, out chan<- string, total *int64, maxTotal int64) {
	runes := []rune(s)
	n := len(runes)
	if m <= 0 || m > n+1 {
		return
	}
	// 逐步回溯生成插入位置，避免一次性分配所有组合
	var backtrack func(start int, cur []int)
	backtrack = func(start int, cur []int) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if len(cur) == m {
			var sb strings.Builder
			prev := 0
			for _, p := range cur {
				sb.WriteString(string(runes[prev:p]))
				ch := 'x'
				var key rune
				if p > 0 {
					key = unicode.ToLower(runes[p-1])
				} else if p < n {
					key = unicode.ToLower(runes[p])
				} else {
					key = 'a'
				}
				if list, ok := dis_character.ConfusablesMap[key]; ok && len(list) > 0 {
					ch = weightedSample(list)
				}
				sb.WriteRune(ch)
				prev = p
			}
			sb.WriteString(string(runes[prev:]))

			if total != nil {
				if atomic.LoadInt64(total) >= maxTotal {
					return
				}
				if atomic.AddInt64(total, 1) > maxTotal {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case out <- sb.String():
			}
			return
		}
		for i := start; i <= n-(m-len(cur)); i++ {
			backtrack(i+1, append(cur, i))
			select {
			case <-ctx.Done():
				return
			default:
			}
			if total != nil && atomic.LoadInt64(total) >= maxTotal {
				return
			}
		}
	}
	backtrack(0, []int{})
}

// deleteMCharsStream: 流式生成 deleteMChars 的变体
func deleteMCharsStream(ctx context.Context, s string, m int, out chan<- string, total *int64, maxTotal int64) {
	runes := []rune(s)
	n := len(runes)
	if n <= m || m <= 0 {
		return
	}
	// 逐步回溯选择删除位置，避免一次性分配所有组合
	var backtrack func(start int, cur []int)
	backtrack = func(start int, cur []int) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if len(cur) == m {
			deleted := make([]bool, n)
			for _, p := range cur {
				deleted[p] = true
			}
			newRunes := make([]rune, 0, n-m)
			for i, r := range runes {
				if !deleted[i] {
					newRunes = append(newRunes, r)
				}
			}

			if total != nil {
				if atomic.LoadInt64(total) >= maxTotal {
					return
				}
				if atomic.AddInt64(total, 1) > maxTotal {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case out <- string(newRunes):
			}
			return
		}
		for i := start; i < n; i++ {
			backtrack(i+1, append(cur, i))
			select {
			case <-ctx.Done():
				return
			default:
			}
			if total != nil && atomic.LoadInt64(total) >= maxTotal {
				return
			}
		}
	}
	backtrack(0, []int{})
}

func insertConfusables(s string, m int) []string {
	runes := []rune(s)
	n := len(runes)
	if m <= 0 || m > n+1 {
		return nil
	}
	positions := insertCombinations(n, m)
	var results []string
	for _, pos := range positions {
		var sb strings.Builder
		prev := 0
		for _, p := range pos {
			sb.WriteString(string(runes[prev:p]))
			ch := 'x'
			var key rune
			if p > 0 {
				key = unicode.ToLower(runes[p-1])
			} else if p < n {
				key = unicode.ToLower(runes[p])
			} else {
				key = 'a'
			}
			if list, ok := dis_character.ConfusablesMap[key]; ok && len(list) > 0 {
				ch = weightedSample(list)
			}
			sb.WriteRune(ch)
			prev = p
		}
		sb.WriteString(string(runes[prev:]))
		results = append(results, sb.String())
	}
	return results
}

func deleteMChars(s string, m int) []string {
	runes := []rune(s)
	n := len(runes)
	if n <= m || m <= 0 {
		return nil
	}
	positions := combinations(n, m)
	results := make([]string, 0, len(positions))
	for _, pos := range positions {
		deleted := make([]bool, n)
		for _, p := range pos {
			deleted[p] = true
		}
		newRunes := make([]rune, 0, n-m)
		for i, r := range runes {
			if !deleted[i] {
				newRunes = append(newRunes, r)
			}
		}
		results = append(results, string(newRunes))
	}
	return results
}

func keyboardReplace(s string, m int) []string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 || m <= 0 || m > n {
		return nil
	}
	positions := combinations(n, m)
	results := make([]string, 0)
	for _, pos := range positions {
		keyboardReplaceOnePos(pos, 0, runes, &results)
	}
	return results
}

func keyboardReplaceOnePos(pos []int, idx int, original []rune, results *[]string) {
	if idx == len(pos) {
		*results = append(*results, string(original))
		return
	}
	currentPos := pos[idx]
	originalChar := original[currentPos]
	lc := unicode.ToLower(originalChar)
	if adj, ok := keyboardAdjacentsWithProb[lc]; ok {
		for _, a := range adj {
			if unicode.IsUpper(originalChar) {
				original[currentPos] = unicode.ToUpper(a.Char)
			} else {
				original[currentPos] = a.Char
			}
			keyboardReplaceOnePos(pos, idx+1, original, results)
			original[currentPos] = originalChar
		}
	} else {
		keyboardReplaceOnePos(pos, idx+1, original, results)
	}
}

func insertDuplicates(s string) []string {
	runes := []rune(s)
	n := len(runes)
	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		nr := make([]rune, 0, n+1)
		nr = append(nr, runes[:i]...)
		nr = append(nr, runes[i])
		nr = append(nr, runes[i:]...)
		results = append(results, string(nr))
	}
	return results
}

func insertHyphens(s string) []string {
	runes := []rune(s)
	n := len(runes)
	if n < 2 {
		return nil
	}
	results := make([]string, 0, n-1)
	for i := 1; i < n; i++ {
		nr := make([]rune, 0, n+1)
		nr = append(nr, runes[:i]...)
		nr = append(nr, '-')
		nr = append(nr, runes[i:]...)
		results = append(results, string(nr))
	}
	return results
}

func concatDictWords(brand string) []string {
	results := make([]string, 0, 2*len(dictWords))
	for _, w := range dictWords {
		results = append(results, w+brand, brand+w)
	}
	return results
}

func swapAdjacentChars(s string) []string {
	runes := []rune(s)
	n := len(runes)
	if n < 2 {
		return nil
	}
	results := make([]string, 0, n-1)
	for i := 0; i < n-1; i++ {
		nr := make([]rune, n)
		copy(nr, runes)
		nr[i], nr[i+1] = nr[i+1], nr[i]
		results = append(results, string(nr))
	}
	return results
}

func replaceMWithRN(s string) (string, bool) {
	if !strings.Contains(strings.ToLower(s), "m") {
		return s, false
	}
	res := strings.ReplaceAll(s, "m", "rn")
	res = strings.ReplaceAll(res, "M", "RN")
	return res, true
}

// --- 封装的工作流核心 ---

func processWorkflow(targetDomain string, threshold float64, outputBaseDir string) {
	domain := strings.TrimSpace(targetDomain)
	if domain == "" {
		return
	}

	fmt.Printf("\n>>> 正在处理: %s\n", domain)

	subdomain, sld, tld := extractDomainParts(domain)
	if sld == "" || tld == "" {
		log.Printf("跳过: 无法解析域名结构 [%s]\n", domain)
		return
	}

	// 1. 创建子目录
	safeName := sanitizeFilename(domain)
	domainOutputDir := filepath.Join(outputBaseDir, safeName)
	os.MkdirAll(domainOutputDir, 0755)

	// 2. 初始化通道（较小缓冲以施加背压，避免短时内存暴涨）
	variantsCh := make(chan string, 512)
	keyboardCh := make(chan string, 512)
	statsCh := make(chan struct {
		op  string
		cnt int
	}, 100)
	var wg sync.WaitGroup
	var punyFileMu sync.Mutex

	// 全局生成限额与上下文，用于流式生成时的早期停止
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var total int64
	// 不限制（尽可能全面），将 maxTotal 设为非常大以避免任意截断；
	// 若需要硬性限制，可通过命令行参数或环境变量传入。
	maxTotal := int64(1 << 62)

	// 3. 开启引擎协程
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(variantsCh)
		defer close(keyboardCh)
		defer close(statsCh)

		send := func(vars []string, op string) {
			if len(vars) == 0 {
				return
			}
			statsCh <- struct {
				op  string
				cnt int
			}{op, len(vars)}
			for _, v := range vars {
				variantsCh <- v
			}
		}
		sendK := func(vars []string, op string) {
			if len(vars) == 0 {
				return
			}
			statsCh <- struct {
				op  string
				cnt int
			}{op, len(vars)}
			for _, v := range vars {
				keyboardCh <- v
			}
		}

		maxM := getMaxReplacements(len(sld))
		for m := 1; m <= maxM; m++ {
			// 使用流式生成以避免一次性在内存中分配大量切片
			replaceWithConfusablesStream(ctx, sld, m, variantsCh, &total, maxTotal)
			insertConfusablesStream(ctx, sld, m, variantsCh, &total, maxTotal)
			deleteMCharsStream(ctx, sld, m, variantsCh, &total, maxTotal)
			sendK(keyboardReplace(sld, m), "键盘替换")
		}
		send(insertDuplicates(sld), "重复字符")
		send(insertHyphens(sld), "插入连字符")
		send(concatDictWords(sld), "字典拼接")
		send(swapAdjacentChars(sld), "相邻交换")
		if s2, ok := replaceMWithRN(sld); ok {
			sendK([]string{s2}, "m->rn替换")
		}
	}()

	// 4. 统计处理协程
	go func() {
		stats := make(map[string]int)
		for s := range statsCh {
			stats[s.op] += s.cnt
		}
		fmt.Printf("[%s] 变体生成统计: ", domain)
		for k, v := range stats {
			fmt.Printf("%s:%d ", k, v)
		}
		fmt.Println()
	}()

	// 5. 结果持久化逻辑 (相似度 + Punycode)
	punyOnlyPath := filepath.Join(domainOutputDir, "puny_only.txt")
	punyF, _ := os.Create(punyOnlyPath)
	punyW := bufio.NewWriter(punyF)

	// 处理键盘变体
	wg.Add(1)
	go func() {
		defer wg.Done()
		kf, _ := os.Create(filepath.Join(domainOutputDir, "keyboard_variants.txt"))
		kw := bufio.NewWriter(kf)
		defer kw.Flush()
		defer kf.Close()
		seenK := make(map[string]struct{})
		for sldVar := range keyboardCh {
			full := sldVar + "." + tld
			if subdomain != "" {
				full = subdomain + "." + full
			}
			if _, ok := seenK[full]; ok {
				continue
			}
			seenK[full] = struct{}{}
			p := toPunycode(full)
			fmt.Fprintf(kw, "%s\t%s\n", full, p)
			punyFileMu.Lock()
			fmt.Fprintln(punyW, p)
			punyFileMu.Unlock()
		}
	}()

	// 处理相似度变体：使用固定数量 worker 并发消费，以利用自然背压并限制内存
	allF, _ := os.Create(filepath.Join(domainOutputDir, "all_variants.txt"))
	highF, _ := os.Create(filepath.Join(domainOutputDir, "high_risk.txt"))
	allW, highW := bufio.NewWriter(allF), bufio.NewWriter(highF)
	defer func() { allW.Flush(); highW.Flush(); allF.Close(); highF.Close() }()

	fmt.Fprintln(allW, "Sim\tDomain\tPunycode")
	fmt.Fprintln(highW, "Sim\tDomain\tPunycode")

	// 并发安全的去重结构
	var seen sync.Map

	// 保护写入的互斥（在 worker 之间共享）
	var allMu sync.Mutex
	var highMu sync.Mutex

	// 启动 worker 池
	workers := runtime.GOMAXPROCS(0)
	if workers <= 0 {
		workers = 4
	}
	if workers > 8 {
		workers = 8
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			for sldVar := range variantsCh {
				full := sldVar + "." + tld
				if subdomain != "" {
					full = subdomain + "." + full
				}
				if _, loaded := seen.LoadOrStore(full, struct{}{}); loaded {
					continue
				}

				sim := visualSimilarity(sld, sldVar)
				p := toPunycode(full)

				// 写入 all_variants（由共享的 allMu 保护）
				allMu.Lock()
				fmt.Fprintf(allW, "%.4f\t%s\t%s\n", sim, full, p)
				allMu.Unlock()

				if sim >= threshold {
					highMu.Lock()
					fmt.Fprintf(highW, "%.4f\t%s\t%s\n", sim, full, p)
					highMu.Unlock()

					// 流式写入 puny_only.txt（立即写盘以避免在内存中累积）
					punyFileMu.Lock()
					fmt.Fprintln(punyW, p)
					punyFileMu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()
	punyW.Flush()
	punyF.Close()
	fmt.Printf("<<< %s 处理完毕，目录: %s\n", domain, domainOutputDir)
}

// --- 程序主入口 ---

func main() {
	domainPtr := flag.String("domain", "", "单个目标域名")
	filePtr := flag.String("file", "", "包含域名列表的文件路径 (每行一个)")
	thresholdPtr := flag.Float64("threshold", 0.98, "视觉相似度阈值")
	flag.Parse()

	// 1. 初始化环境
	const confusablesDir = "dis_character"
	if err := dis_character.LoadConfusables(confusablesDir); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	outputBase := "domain_variants"
	os.MkdirAll(outputBase, 0755)

	// 2. 逻辑分发
	if *filePtr != "" {
		// 文件批量模式
		f, err := os.Open(*filePtr)
		if err != nil {
			log.Fatalf("无法读取文件: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processWorkflow(scanner.Text(), *thresholdPtr, outputBase)
		}
	} else if *domainPtr != "" {
		// 命令行单域名模式
		processWorkflow(*domainPtr, *thresholdPtr, outputBase)
	} else {
		// 交互模式
		fmt.Print("请输入目标域名: ")
		var input string
		fmt.Scanln(&input)
		processWorkflow(input, *thresholdPtr, outputBase)
	}

	fmt.Println("\n所有任务已结束。")
}
