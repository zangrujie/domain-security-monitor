package dis_character

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type ConfusableChar struct {
	Char       rune
	Similarity float64
}

// ConfusablesMap存放所有字母的相似字符文件
var ConfusablesMap = make(map[rune][]ConfusableChar)

func LoadConfusables(dirPath string) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("无法读取目录%s:%w", dirPath, err)
	}

	// 正则匹配文件名开头字母
	reFile := regexp.MustCompile(`^([a-zA-Z])_similarity_`)

	for _, file := range files {
		if file.IsDir() { //跳过子目录，只处理文件
			continue
		}

		//使用正则匹配文件名，判断是否为目标文件名
		m := reFile.FindStringSubmatch(file.Name())
		if len(m) != 2 {
			continue
		}

		baseChar := unicode.ToLower(rune(m[1][0]))
		path := filepath.Join(dirPath, file.Name())

		f, err := os.Open(path)
		if err != nil {
			fmt.Printf("⚠️ 无法打开文件 %s: %v\n", file.Name(), err)
			continue
		}
		defer f.Close() // 改用 defer 确保文件关闭（更安全）

		scanner := bufio.NewScanner(f)
		//逐行读取输入流，会一行一行的读取内容直到遇到EOF为止
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			//跳过空行、注释行（#开头）、非数据行（非“-”开头）
			if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "-") {
				continue
			}
			line = strings.TrimPrefix(line, "- ")

			quoteParts := strings.Split(line, "'")
			if len(quoteParts) < 3 {
				continue
			}
			charStr := quoteParts[1] //提取单引号中的字符

			numPart := strings.TrimSpace(quoteParts[2])
			numParts := strings.Fields(numPart)
			if len(numParts) < 1 {
				continue
			}
			simStr := numParts[0] //提取字符串部分

			if len(charStr) == 0 {
				continue
			}
			ch := []rune(charStr)[0]

			sim, err := strconv.ParseFloat(simStr, 64)
			if err != nil {
				fmt.Printf("行格式错误（数值解析失败）：%s\n", line)
				continue
			}

			ConfusablesMap[baseChar] = append(ConfusablesMap[baseChar], ConfusableChar{
				Char:       ch,
				Similarity: sim,
			})
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("文件扫描错误%s:%v\n", file.Name(), err)
		}
	}
	return nil
}
