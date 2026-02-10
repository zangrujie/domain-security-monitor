/*
package main

import (
	"MySecurityProject/dis_character" // 保持原有包引用
	"bufio"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// 键盘相邻字符及其概率
type AdjacentChar struct {
	Char  rune    //相邻的字符
	Value float64 //该字符对应的概率值
}

// ConfusableChar结构体用来存储相似字符及其相似度
type ConfusableChar struct {
	Char       rune
	Similarity float64
}

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

const SimilarityThreshold = 0.98

var (
	replaceStats   []ReplaceStats
	replaceStatsMu sync.Mutex
)

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

var dictWords = []string{"login", "secure", "update", "auth", "verify", "account", "user", "my"}
var illegalFilenameChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)

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

func replaceMWithRN(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	var b strings.Builder
	replaced := false
	for _, r := range s {
		if r == 'm' {
			b.WriteString("rn")
			replaced = true
		} else if r == 'M' {
			b.WriteString("RN")
			replaced = true
		} else {
			b.WriteRune(r)
		}
	}
	if !replaced {
		return s, false
	}
	return b.String(), true
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
					recordReplace(o[i], v[j])
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

func recordReplace(from, to rune) {
	replaceStatsMu.Lock()
	defer replaceStatsMu.Unlock()
	for i := range replaceStats {
		if replaceStats[i].From == from && replaceStats[i].To == to {
			replaceStats[i].Count++
			return
		}
	}
	replaceStats = append(replaceStats, ReplaceStats{From: from, To: to, Count: 1})
}

func computeReplaceStatsFromHighRisk(orig string, highRisk []Scored) []ReplaceStats {
	counts := make(map[string]int)
	oRunes := []rune(strings.ToLower(orig))
	n := len(oRunes)

	for _, h := range highRisk {
		parts := strings.Split(h.domain, ".")
		var variantSLD string
		if len(parts) >= 2 {
			variantSLD = strings.Split(h.domain, ".")[0]
		} else {
			variantSLD = h.domain
		}

		vRunes := []rune(strings.ToLower(variantSLD))
		m := len(vRunes)

		dp := make([][]float64, n+1)
		for i := range dp {
			dp[i] = make([]float64, m+1)
		}
		for i := 0; i <= n; i++ {
			dp[i][0] = float64(i)
		}
		for j := 0; j <= m; j++ {
			dp[0][j] = float64(j)
		}

		for i := 1; i <= n; i++ {
			for j := 1; j <= m; j++ {
				cost := 1.0
				if oRunes[i-1] == vRunes[j-1] {
					cost = 0.0
				} else if list, ok := dis_character.ConfusablesMap[oRunes[i-1]]; ok {
					for _, c := range list {
						if c.Char == vRunes[j-1] {
							cost = 1.0 - c.Similarity
							break
						}
					}
				}
				dp[i][j] = math.Min(math.Min(dp[i-1][j]+1, dp[i][j-1]+1), dp[i-1][j-1]+cost)
			}
		}

		i, j := n, m
		for i > 0 && j > 0 {
			current := dp[i][j]
			up := dp[i-1][j]
			left := dp[i][j-1]
			if current <= up+1e-9 && current <= left+1e-9 {
				if oRunes[i-1] != vRunes[j-1] {
					if isConfusable(oRunes[i-1], vRunes[j-1]) {
						key := fmt.Sprintf("%c|%c", oRunes[i-1], vRunes[j-1])
						counts[key]++
					}
				}
				i--
				j--
			} else if up < left {
				i--
			} else {
				j--
			}
		}
	}
	return formatAndSortStats(counts)
}

func formatAndSortStats(counts map[string]int) []ReplaceStats {
	var res []ReplaceStats
	for k, v := range counts {
		parts := strings.Split(k, "|")
		if len(parts) != 2 {
			continue
		}
		fromRunes := []rune(parts[0])
		toRunes := []rune(parts[1])
		if len(fromRunes) == 0 || len(toRunes) == 0 {
			continue
		}
		res = append(res, ReplaceStats{From: fromRunes[0], To: toRunes[0], Count: v})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Count > res[j].Count })
	return res
}

func isConfusable(from, to rune) bool {
	list, ok := dis_character.ConfusablesMap[from]
	if !ok {
		return false
	}
	for _, c := range list {
		if c.Char == to {
			return true
		}
	}
	return false
}

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
	adjacentCharsWithProb, ok := keyboardAdjacentsWithProb[lc]
	if !ok {
		keyboardReplaceOnePos(pos, idx+1, original, results)
		return
	}
	for _, adj := range adjacentCharsWithProb {
		ch := adj.Char
		if unicode.IsUpper(originalChar) {
			original[currentPos] = unicode.ToUpper(ch)
		} else {
			original[currentPos] = ch
		}
		keyboardReplaceOnePos(pos, idx+1, original, results)
	}
	original[currentPos] = originalChar
}

func insertDuplicates(s string) []string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 {
		return nil
	}
	results := make([]string, 0, n)
	for i := 0; i < n; i++ {
		newRunes := make([]rune, 0, n+1)
		newRunes = append(newRunes, runes[:i]...)
		newRunes = append(newRunes, runes[i])
		newRunes = append(newRunes, runes[i:]...)
		results = append(results, string(newRunes))
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
		newRunes := make([]rune, 0, n+1)
		newRunes = append(newRunes, runes[:i]...)
		newRunes = append(newRunes, '-')
		newRunes = append(newRunes, runes[i:]...)
		results = append(results, string(newRunes))
	}
	return results
}

func concatDictWords(brand string) []string {
	results := make([]string, 0, 2*len(dictWords))
	for _, word := range dictWords {
		results = append(results, word+brand)
	}
	for _, word := range dictWords {
		results = append(results, brand+word)
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
		newRunes := make([]rune, n)
		copy(newRunes, runes)
		newRunes[i], newRunes[i+1] = newRunes[i+1], newRunes[i]
		results = append(results, string(newRunes))
	}
	return results
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

func toPunycode(domain string) string {
	p, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return p
}

// ------------------------------
// 主函数
// ------------------------------

func main() {
	// 1. 定义并解析命令行参数
	// -domain: 目标域名
	// -threshold: 相似度阈值（可选，默认 0.98，增加项目灵活性）
	domainPtr := flag.String("domain", "", "要处理的目标域名 (例如: example.com)")
	thresholdPtr := flag.Float64("threshold", 0.98, "视觉相似度阈值 (0.0-1.0)")
	flag.Parse()

	domain := *domainPtr

	// 2. 如果命令行没有提供参数，则退回到手动输入模式
	if domain == "" {
		fmt.Print("未检测到命令行参数，请输入要处理的域名：")
		fmt.Scanln(&domain)
	}

	// 再次校验，如果依然为空则退出
	domain = strings.TrimSpace(domain)
	if domain == "" {
		log.Println("错误: 域名不能为空")
		return
	}

	// 3. 加载相似字符表
	const confusablesDir = "dis_character"
	if err := dis_character.LoadConfusables(confusablesDir); err != nil {
		log.Fatalf("加载相似字符失败: %v", err)
	}
	fmt.Printf("成功加载 %d 个字符的相似表\n", len(dis_character.ConfusablesMap))
	fmt.Printf("当前设定的相似度阈值: %.2f\n", *thresholdPtr)

	// 4. 解析域名
	subdomain, sld, tld := extractDomainParts(domain)
	if sld == "" || tld == "" {
		log.Printf("错误: 无法解析域名结构 [%s]\n", domain)
		return
	}
	maxM := getMaxReplacements(len(sld))

	// 5. 输出目录与文件初始化
	outputDir := "domain_variants"
	os.MkdirAll(outputDir, 0755)
	baseName := sanitizeFilename(domain)

	allFile := filepath.Join(outputDir, baseName+"_all.txt")
	highFile := filepath.Join(outputDir, baseName+"_high_risk.txt")
	punyOnlyFile := filepath.Join(outputDir, baseName+"_puny_only.txt")

	// 6. 通道与同步控制
	variantsCh := make(chan string, 2000)
	keyboardCh := make(chan string, 2000)
	statsCh := make(chan struct {
		op  string
		cnt int
	}, 50)

	var wg sync.WaitGroup
	var punyFileMu sync.Mutex

	// ==============================================================
	// 协程 1：并发生成变体逻辑 (保持不变)
	// ==============================================================
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

		sendKeyboard := func(vars []string, op string) {
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

		for m := 1; m <= maxM; m++ {
			send(replaceWithConfusables(sld, m), "相似替换")
			send(insertConfusables(sld, m), "相似插入")
			send(deleteMChars(sld, m), "删除字符")
			sendKeyboard(keyboardReplace(sld, m), "键盘替换")
		}
		send(insertDuplicates(sld), "重复字符")
		send(insertHyphens(sld), "插入连字符")
		send(concatDictWords(sld), "字典拼接")
		send(swapAdjacentChars(sld), "相邻交换")
		if s2, ok := replaceMWithRN(sld); ok {
			sendKeyboard([]string{s2}, "m->rn替换")
		}
	}()

	// 提前创建 punyOnlyFile
	punyF, _ := os.Create(punyOnlyFile)
	punyW := bufio.NewWriter(punyF)

	// ==============================================================
	// 协程 2：处理键盘变体 (写入 punyOnly)
	// ==============================================================
	wg.Add(1)
	go func() {
		defer wg.Done()
		kf, _ := os.Create(filepath.Join(outputDir, baseName+"_keyboard.txt"))
		kw := bufio.NewWriter(kf)
		defer kf.Close()
		defer kw.Flush()

		seenK := make(map[string]struct{})
		for sldVar := range keyboardCh {
			var full string
			if subdomain != "" {
				full = subdomain + "." + sldVar + "." + tld
			} else {
				full = sldVar + "." + tld
			}
			if _, ok := seenK[full]; ok {
				continue
			}
			seenK[full] = struct{}{}

			puny := toPunycode(full)
			fmt.Fprintf(kw, "%s\t%s\n", full, puny)

			punyFileMu.Lock()
			fmt.Fprintln(punyW, puny)
			punyFileMu.Unlock()
		}
	}()

	// ==============================================================
	// 协程 3：处理相似度变体 (使用动态阈值 *thresholdPtr)
	// ==============================================================
	wg.Add(1)
	go func() {
		defer wg.Done()
		allF, _ := os.Create(allFile)
		highF, _ := os.Create(highFile)
		defer allF.Close()
		defer highF.Close()
		allW := bufio.NewWriter(allF)
		highW := bufio.NewWriter(highF)
		defer allW.Flush()
		defer highW.Flush()

		fmt.Fprintf(allW, "Type\tSimilarity\tUnicode_Domain\tPunycode_Domain\n")
		fmt.Fprintf(highW, "Type\tSimilarity\tUnicode_Domain\tPunycode_Domain\n")

		var highRisk []Scored
		seen := make(map[string]struct{})

		for sldVar := range variantsCh {
			var full string
			if subdomain != "" {
				full = subdomain + "." + sldVar + "." + tld
			} else {
				full = sldVar + "." + tld
			}
			if _, ok := seen[full]; ok {
				continue
			}
			seen[full] = struct{}{}

			sim := visualSimilarity(sld, sldVar)
			puny := toPunycode(full)
			fmt.Fprintf(allW, "[NORMAL]\t%.6f\t%s\t%s\n", sim, full, puny)

			// 使用解析出来的阈值
			if sim >= *thresholdPtr {
				isUnicode := false
				for _, r := range sldVar {
					if r > 127 {
						isUnicode = true
						break
					}
				}
				highRisk = append(highRisk, Scored{full, puny, sim, isUnicode})

				punyFileMu.Lock()
				fmt.Fprintln(punyW, puny)
				punyFileMu.Unlock()
			}
		}

		sort.Slice(highRisk, func(i, j int) bool { return highRisk[i].sim > highRisk[j].sim })
		for _, v := range highRisk {
			tag := "[ASCII   ]"
			if v.isUni {
				tag = "[UNICODE]"
			}
			fmt.Fprintf(highW, "%s\t%.6f\t%s\t%s\n", tag, v.sim, v.domain, v.punycode)
		}
	}()

	// ==============================================================
	// 协程 4：统计模块
	// ==============================================================
	wg.Add(1)
	go func() {
		defer wg.Done()
		stats := make(map[string]int)
		for s := range statsCh {
			stats[s.op] += s.cnt
		}
		fmt.Println("\n=== 各攻击类型生成数量统计 ===")
		for op, c := range stats {
			fmt.Printf("%-12s : %d\n", op, c)
		}
	}()

	wg.Wait()
	punyW.Flush()
	punyF.Close()
	fmt.Printf("\n任务完成！\n纯 Punycode 列表已生成：%s (供 xdig 使用)\n", punyOnlyFile)
}*/

package main

import (
	"MySecurityProject/dis_character"
	"bufio"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

	// 2. 初始化通道
	variantsCh := make(chan string, 5000)
	keyboardCh := make(chan string, 5000)
	statsCh := make(chan struct {
		op  string
		cnt int
	}, 100)
	var wg sync.WaitGroup
	var punyFileMu sync.Mutex

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
			send(replaceWithConfusables(sld, m), "相似替换")
			send(insertConfusables(sld, m), "相似插入")
			send(deleteMChars(sld, m), "删除字符")
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

	// 处理相似度变体
	wg.Add(1)
	go func() {
		defer wg.Done()
		allF, _ := os.Create(filepath.Join(domainOutputDir, "all_variants.txt"))
		highF, _ := os.Create(filepath.Join(domainOutputDir, "high_risk.txt"))
		allW, highW := bufio.NewWriter(allF), bufio.NewWriter(highF)
		defer func() { allW.Flush(); highW.Flush(); allF.Close(); highF.Close() }()

		fmt.Fprintln(allW, "Sim\tDomain\tPunycode")
		fmt.Fprintln(highW, "Sim\tDomain\tPunycode")

		seen := make(map[string]struct{})
		for sldVar := range variantsCh {
			full := sldVar + "." + tld
			if subdomain != "" {
				full = subdomain + "." + full
			}
			if _, ok := seen[full]; ok {
				continue
			}
			seen[full] = struct{}{}

			sim := visualSimilarity(sld, sldVar)
			p := toPunycode(full)
			fmt.Fprintf(allW, "%.4f\t%s\t%s\n", sim, full, p)

			if sim >= threshold {
				fmt.Fprintf(highW, "%.4f\t%s\t%s\n", sim, full, p)
				punyFileMu.Lock()
				fmt.Fprintln(punyW, p)
				punyFileMu.Unlock()
			}
		}
	}()

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
